"""
Бот мониторинга отзывов, оценок и платежей RuStore.

Отслеживает новые/изменённые отзывы, оценки без текста и платежи
в RuStore, отправляя уведомления в Telegram-чат.

Переменные окружения:
    RUSTORE_KEY_ID       — id ключа API
    RUSTORE_PRIVATE_KEY  — приватный ключ в формате base64
    RUSTORE_PACKAGE_NAME — имя пакета приложения (например, com.example.app)
    RUSTORE_APP_ID       — числовой id приложения из консоли RuStore
    TELEGRAM_DOMAIN      — домен Telegram API (по умолчанию api.telegram.org)
    TELEGRAM_BOT_TOKEN   — токен Telegram-бота
    TELEGRAM_CHAT_ID     — id чата для уведомлений
    TELEGRAM_THREAD_ID   — id темы в супергруппе (опционально)
    POLL_INTERVAL        — интервал опроса в секундах (по умолчанию 300)
    TZ_OFFSET            — смещение часового пояса в часах (по умолчанию +3, МСК)
"""

import os
import sys
import time
import base64
import logging
import sqlite3
import datetime
from pathlib import Path

import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

RUSTORE_AUTH_URL = "https://public-api.rustore.ru/public/auth"
RUSTORE_API_BASE = "https://public-api.rustore.ru/public/v1/application"
RUSTORE_PAYMENTS_BASE = "https://public-api.rustore.ru/public/applications"
DB_FILE = Path("/data/state.db")  # база состояния внутри Docker-тома

# ── конфигурация из переменных окружения ──

KEY_ID = os.environ["RUSTORE_KEY_ID"]
PRIVATE_KEY_B64 = os.environ["RUSTORE_PRIVATE_KEY"]
PACKAGE_NAME = os.environ["RUSTORE_PACKAGE_NAME"]
APP_ID = os.environ["RUSTORE_APP_ID"]
TELEGRAM_DOMAIN = os.environ.get("TELEGRAM_DOMAIN") or "api.telegram.org"
TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
TELEGRAM_THREAD_ID = os.environ.get("TELEGRAM_THREAD_ID")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL") or "300")
TZ_OFFSET = int(os.environ.get("TZ_OFFSET") or "3")
LOCAL_TZ = datetime.timezone(datetime.timedelta(hours=TZ_OFFSET))

# ── авторизация RuStore ──

_cached_token = None
_token_expires_at = 0


def get_rustore_token() -> str:
    """Получает JWE-токен RuStore, кеширует до истечения TTL."""
    global _cached_token, _token_expires_at

    now = time.time()
    if _cached_token and now < _token_expires_at - 30:
        return _cached_token

    # подписываем запрос приватным RSA-ключом (SHA-512 + PKCS1 v1.5)
    private_key = RSA.import_key(base64.b64decode(PRIVATE_KEY_B64))

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
    message = KEY_ID + timestamp

    h = SHA512.new(message.encode())
    signature = base64.b64encode(pkcs1_15.new(private_key).sign(h)).decode()

    resp = requests.post(
        RUSTORE_AUTH_URL,
        json={"keyId": KEY_ID, "timestamp": timestamp, "signature": signature},
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()

    if data.get("code") != "OK":
        raise RuntimeError(f"Ошибка авторизации RuStore: {data.get('message')}")

    _cached_token = data["body"]["jwe"]
    _token_expires_at = now + data["body"]["ttl"]
    log.info("Токен RuStore получен, ttl=%dс", data["body"]["ttl"])
    return _cached_token


# ── запросы к API RuStore ──


def _rustore_get(url: str, label: str, **kwargs) -> dict:
    """Выполняет GET-запрос к API RuStore с авторизацией и проверкой ответа."""
    token = get_rustore_token()
    resp = requests.get(
        url,
        headers={"Public-Token": token},
        timeout=15,
        **kwargs,
    )
    resp.raise_for_status()
    data = resp.json()
    if data.get("code") != "OK":
        raise RuntimeError(f"Ошибка {label}: {data.get('message')}")
    return data["body"]


def fetch_rating() -> dict:
    """Получает статистику оценок приложения."""
    return _rustore_get(
        f"{RUSTORE_API_BASE}/{PACKAGE_NAME}/comment/statistic",
        "получения рейтинга",
    )


def fetch_reviews(size: int = 100) -> list[dict]:
    """Получает список последних отзывов."""
    return _rustore_get(
        f"{RUSTORE_API_BASE}/{PACKAGE_NAME}/comment",
        "получения отзывов",
        params={"size": size},
    )


def fetch_products() -> list[dict]:
    """Получает список продуктов (разовые покупки)."""
    body = _rustore_get(
        f"{RUSTORE_PAYMENTS_BASE}/{APP_ID}/catalog/products",
        "получения продуктов",
    )
    return body.get("elements", [])


def fetch_subscriptions() -> list[dict]:
    """Получает список подписок."""
    body = _rustore_get(
        f"{RUSTORE_PAYMENTS_BASE}/{APP_ID}/catalog/subscriptions",
        "получения подписок",
    )
    return body.get("elements", [])


_products_cache: dict[str, str] = {}


def all_products_map() -> dict[str, str]:
    """Возвращает кешированный словарь productId → name. Загружает при первом вызове."""
    global _products_cache
    if not _products_cache:
        _refresh_products_cache()
    return _products_cache


def _refresh_products_cache():
    """Перезагружает словарь продуктов и подписок из API."""
    global _products_cache
    items = fetch_products() + fetch_subscriptions()
    _products_cache = {
        item["productId"]: item["name"]
        for item in items
    }
    log.info("Кеш продуктов обновлён, %d записей", len(_products_cache))


def fetch_invoices(date: str) -> list[dict]:
    """Получает подтверждённые платежи за указанную дату."""
    body = _rustore_get(
        f"{RUSTORE_PAYMENTS_BASE}/{APP_ID}/invoices",
        "получения платежей",
        params={"invoiceStatuses": "confirmed", "invoiceDate": date},
    )
    return body.get("content", [])


def detect_new_invoices(invoices: list[dict], old_ids: set[int]) -> list[dict]:
    """Фильтрует только новые платежи, которых нет в old_ids."""
    return [inv for inv in invoices if inv["invoiceId"] not in old_ids]


def format_payment_method(payment: dict) -> str:
    """Форматирует способ оплаты в читаемую строку."""
    if not payment:
        return ""

    way = payment.get("paymentWay")
    system = payment.get("paymentSystem")
    pan = payment.get("maskedPan")
    bank = payment.get("bankName")

    parts = []

    if way:
        parts.append(way)

    if system:
        parts.append(system.upper())

    if pan:
        parts.append(pan)

    if bank:
        parts.append(f"({bank})")

    return " ".join(parts)


def resolve_product_name(order: dict, products_map: dict) -> str:
    """Определяет название продукта по itemCode. При промахе кеша — перезагружает."""
    code = order.get("itemCode")
    if not code:
        return order.get("visualName") or "—"
    if code in products_map:
        return products_map[code]
    # ключ не найден — перезагружаем кеш
    _refresh_products_cache()
    return _products_cache.get(code) or order.get("visualName") or "—"


# ── состояние (SQLite) ──


def _get_db() -> sqlite3.Connection:
    """Возвращает соединение с БД, создаёт таблицы при первом вызове."""
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS reviews (
            comment_id INTEGER PRIMARY KEY,
            edited     INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS invoices (
            invoice_id   INTEGER PRIMARY KEY,
            invoice_date TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ratings (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    return conn


def load_comment_ids(conn: sqlite3.Connection) -> set[int]:
    return {row[0] for row in conn.execute("SELECT comment_id FROM reviews")}


def load_edited_ids(conn: sqlite3.Connection) -> set[int]:
    return {row[0] for row in conn.execute("SELECT comment_id FROM reviews WHERE edited = 1")}


def load_ratings(conn: sqlite3.Connection) -> dict[str, int]:
    return {row[0]: row[1] for row in conn.execute("SELECT key, value FROM ratings")}


def load_invoice_ids(conn: sqlite3.Connection, today: str) -> set[int]:
    return {row[0] for row in conn.execute(
        "SELECT invoice_id FROM invoices WHERE invoice_date = ?", (today,)
    )}


def has_invoice_date(conn: sqlite3.Connection, today: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM invoices WHERE invoice_date = ? LIMIT 1", (today,)
    ).fetchone()
    return row is not None


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def save_reviews(conn: sqlite3.Connection, comment_ids: set[int], edited_ids: set[int]):
    conn.execute("DELETE FROM reviews")
    conn.executemany(
        "INSERT INTO reviews (comment_id, edited) VALUES (?, ?)",
        [(cid, 1 if cid in edited_ids else 0) for cid in comment_ids],
    )


def save_invoices(conn: sqlite3.Connection, invoice_ids: set[int], today: str):
    conn.executemany(
        "INSERT OR IGNORE INTO invoices (invoice_id, invoice_date) VALUES (?, ?)",
        [(iid, today) for iid in invoice_ids],
    )


def save_ratings(conn: sqlite3.Connection, ratings: dict):
    conn.execute("DELETE FROM ratings")
    conn.executemany(
        "INSERT INTO ratings (key, value) VALUES (?, ?)",
        list(ratings.items()),
    )


def save_meta(conn: sqlite3.Connection, **kwargs):
    conn.executemany(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
        list(kwargs.items()),
    )


# ── отправка в Telegram ──


def tg_send(text: str):
    """Отправляет HTML-сообщение в Telegram-чат."""
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    if TELEGRAM_THREAD_ID:
        payload["message_thread_id"] = int(TELEGRAM_THREAD_ID)
    resp = requests.post(
        f"https://{TELEGRAM_DOMAIN}/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        json=payload,
        timeout=15,
    )
    if not resp.ok:
        log.error("Telegram send error: %s", resp.text)


# ── форматирование сообщений ──

RATING_NAMES = {
    "amountFive": 5,
    "amountFour": 4,
    "amountThree": 3,
    "amountTwo": 2,
    "amountOne": 1,
}

def calculate_avg(ratings: dict) -> float:
    """Вычисляет средний рейтинг по распределению оценок."""
    total = sum(ratings.values())
    if total == 0:
        return 0.0

    s = (
        ratings.get("amountFive", 0) * 5 +
        ratings.get("amountFour", 0) * 4 +
        ratings.get("amountThree", 0) * 3 +
        ratings.get("amountTwo", 0) * 2 +
        ratings.get("amountOne", 0) * 1
    )
    return s / total

def format_stats(rating: dict) -> str:
    r = rating["ratings"]
    api_avg = rating["averageUserRating"]
    total = rating["totalRatings"]

    calc_avg = calculate_avg(r)

    # проверка расхождения между API и вычисленным средним
    diff = abs(api_avg - calc_avg)

    if diff > 0.01:
        avg_str = f"★ {api_avg:.2f} (API) • {calc_avg:.2f} (calc) ⚠️"
    else:
        avg_str = f"★ {api_avg:.2f}"

    return (
        f"📊 <b>Статистика:</b>\n"
        f"{avg_str} ({total} оц.)\n"
        f"⭐5 — {r['amountFive']}  "
        f"⭐4 — {r['amountFour']}  "
        f"⭐3 — {r['amountThree']}  "
        f"⭐2 — {r['amountTwo']}  "
        f"⭐1 — {r['amountOne']}"
    )



def format_new_review(review: dict, rating: dict) -> str:
    stars = "⭐" * review["appRating"]
    version = f"  •  v{review['appVersionName']}" if review.get("appVersionName") else ""
    edited = "  (ред.)" if review.get("edited") else ""
    return (
        f"📝 <b>Новый отзыв в RuStore</b>\n\n"
        f"{stars}  •  {review['userName']}{version}{edited}\n"
        f"«{review['commentText']}»\n\n"
        f"{format_stats(rating)}"
    )


def format_edited_review(review: dict, rating: dict) -> str:
    stars = "⭐" * review["appRating"]
    version = f"  •  v{review['appVersionName']}" if review.get("appVersionName") else ""
    return (
        f"✏️ <b>Отзыв изменён</b>\n\n"
        f"{stars}  •  {review['userName']}{version}\n"
        f"«{review['commentText']}»\n\n"
        f"{format_stats(rating)}"
    )


def format_silent_ratings(changes: dict[int, int], rating: dict) -> str:
    parts = []
    for star, delta in sorted(changes.items(), reverse=True):
        if delta > 0:
            parts.append(f"+{delta} × {star}⭐")
        elif delta < 0:
            parts.append(f"{delta} × {star}⭐")
    changes_str = ",  ".join(parts)
    return (
        f"⭐ <b>Новая оценка:</b> {changes_str}\n\n"
        f"{format_stats(rating)}"
    )


def format_new_invoice(inv: dict, products_map: dict) -> str:
    order = inv.get("order", {})
    payment = inv.get("paymentInfo", {})

    amount = order.get("amountCurrent", 0) // 100
    currency = order.get("currency", "RUB")
    if currency == "RUB":
        currency = "₽"

    visualName = order.get("visualName")
    name = resolve_product_name(order, products_map)

    pay_date = payment.get("paymentDate") or inv.get("invoiceDate")
    method = format_payment_method(payment)


    lines = [
        "💰 <b>Новый платёж</b>",
        "",
        f"<b>{visualName}</b>",
        f"<b>Продукт:</b> {name}",
        f"<b>Сумма:</b> {amount} {currency}",
        "",
        f"<b>Дата:</b> {pay_date}",
    ]

    if method:
        lines.append(f"<b>Способ оплаты:</b> {method}")

    return "\n".join(lines)


# ── основной цикл ──


def check_updates():
    """Проверяет новые отзывы, изменения оценок и платежи, отправляет уведомления."""
    conn = _get_db()
    try:
        old_comment_ids = load_comment_ids(conn)
        old_ratings = load_ratings(conn)
        old_edited = load_edited_ids(conn)

        rating = fetch_rating()
        reviews = fetch_reviews()

        current_comment_ids = {r["commentId"] for r in reviews}
        current_edited = {r["commentId"] for r in reviews if r.get("edited")}

        messages = []

        # новые отзывы (пропускаем при первом запуске)
        new_ids = current_comment_ids - old_comment_ids
        if old_comment_ids:
            for review in reviews:
                if review["commentId"] in new_ids:
                    messages.append(format_new_review(review, rating))

        # отредактированные отзывы
        newly_edited = current_edited - old_edited
        if old_comment_ids:
            for review in reviews:
                if review["commentId"] in newly_edited and review["commentId"] not in new_ids:
                    messages.append(format_edited_review(review, rating))

        # «тихие» оценки без текста — обнаруживаем по изменению распределения
        if old_ratings and not new_ids:
            changes = {}
            for key, star in RATING_NAMES.items():
                diff = rating["ratings"].get(key, 0) - old_ratings.get(key, 0)
                if diff != 0:
                    changes[star] = diff
            if changes:
                messages.append(format_silent_ratings(changes, rating))

        # ── проверка платежей ──
        today = datetime.datetime.now(LOCAL_TZ).strftime("%Y-%m-%d")
        current_invoice_ids: set[int] = set()

        try:
            invoices = fetch_invoices(today)

            old_invoice_ids = load_invoice_ids(conn, today)
            current_invoice_ids = {inv["invoiceId"] for inv in invoices}

            new_invoices = detect_new_invoices(invoices, old_invoice_ids)

            is_first_run = get_meta(conn, "payments_initialized") is None

            log.info(
                "Payments: total=%d, old=%d, new=%d, first_run=%s",
                len(invoices),
                len(old_invoice_ids),
                len(new_invoices),
                is_first_run,
            )

            # отправляем ТОЛЬКО если это не первый запуск
            if not is_first_run and new_invoices:
                products_map = all_products_map()

                for inv in new_invoices:
                    msg = format_new_invoice(inv, products_map)
                    messages.append(msg)

            # помечаем, что инициализация была
            if is_first_run:
                save_meta(conn, payments_initialized="1")

        except Exception as e:
            log.exception("Ошибка при проверке платежей: %s", e)

        # отправляем уведомления в Telegram
        for msg in messages:
            tg_send(msg)
            time.sleep(0.5)

        if not old_comment_ids:
            log.info("Первый запуск — сохраняю начальное состояние (%d отзывов)", len(reviews))

        # сохраняем текущее состояние для следующей проверки
        save_reviews(conn, current_comment_ids, current_edited)
        save_invoices(conn, current_invoice_ids, today)
        save_ratings(conn, rating["ratings"])
        save_meta(
            conn,
            total_ratings=str(rating["totalRatings"]),
            average=str(rating["averageUserRating"]),
            last_check=datetime.datetime.now(LOCAL_TZ).isoformat(),
        )
        conn.commit()
    finally:
        conn.close()


def main():
    log.info("RuStore monitor запущен, пакет=%s, интервал=%ds", PACKAGE_NAME, POLL_INTERVAL)

    # проверяем подключение при старте
    try:
        token = get_rustore_token()
        log.info("Авторизация OK")
    except Exception as e:
        log.error("Ошибка авторизации: %s", e)
        sys.exit(1)

    while True:
        try:
            check_updates()
            log.info("Проверка завершена")
        except Exception as e:
            log.exception("Ошибка при проверке: %s", e)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()