"""Основной цикл мониторинга RuStore.

Каждая проверка возвращает список сообщений и функцию сохранения состояния.
Состояние проверки сохраняется только после успешной отправки всех её
сообщений, поэтому при сбое доставки уведомления переотправятся на следующей
итерации. Ошибка одной проверки (например, у ключа нет доступа к методу) не
мешает остальным.
"""

import sys
import time
import logging
import json
import datetime
from typing import Callable

from . import config, state, rustore, formatting
from .notifiers import notify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

CheckResult = tuple[list[str], Callable[[], None]]


def _absorb(changes: dict[int, int], star: int, delta: int):
    """Вычитает из diff'а распределения изменение, уже объяснённое отзывом.

    Вычитаем, только если diff по этой звезде того же знака — иначе статистика
    ещё не обновилась, и «объяснять» в ней нечего.
    """
    if changes.get(star, 0) * delta > 0:
        changes[star] -= delta
        if changes[star] == 0:
            del changes[star]


def check_reviews(conn, app: config.App) -> CheckResult:
    """Новые и изменённые отзывы, «тихие» оценки без текста."""
    old_reviews = state.load_reviews(conn)
    old_ratings = state.load_ratings(conn)
    # пустой список отзывов у нового приложения — не повод считать каждый запуск первым
    is_first_run = not old_reviews and state.get_meta(conn, "reviews_initialized") is None

    rating = rustore.fetch_rating(app)
    reviews = rustore.fetch_reviews(app)

    new_reviews: list[dict] = []
    edited: list[tuple[dict, int, str]] = []
    if not is_first_run:
        for review in reviews:
            cid = review["commentId"]
            if cid not in old_reviews:
                new_reviews.append(review)
                continue
            old_rating, old_text = old_reviews[cid]
            if old_rating is None:
                continue  # строка из старой схемы — сравнивать не с чем
            if (old_rating, old_text) != (review["appRating"], review.get("commentText") or ""):
                edited.append((review, old_rating, old_text))

    messages = [formatting.format_new_review(r, rating) for r in new_reviews]
    messages += [formatting.format_edited_review(r, old_r, old_t, rating) for r, old_r, old_t in edited]

    # «тихие» оценки без текста — обнаруживаем по изменению распределения.
    # Вклад новых и изменённых отзывов из diff'а вычитаем, чтобы не дублировать уведомления.
    if old_ratings:
        changes: dict[int, int] = {}
        for key, star in formatting.RATING_NAMES.items():
            diff = rating["ratings"].get(key, 0) - old_ratings.get(key, 0)
            if diff != 0:
                changes[star] = diff
        for review in new_reviews:
            _absorb(changes, review["appRating"], +1)
        for review, old_rating, _ in edited:
            if old_rating != review["appRating"]:
                _absorb(changes, old_rating, -1)
                _absorb(changes, review["appRating"], +1)
        if changes:
            messages.append(formatting.format_silent_ratings(changes, rating))

    def save():
        if is_first_run:
            log.info("%s: первый запуск — сохраняю начальное состояние (%d отзывов)", app.package, len(reviews))
        state.save_reviews(conn, reviews)
        state.save_ratings(conn, rating["ratings"])
        state.save_meta(
            conn,
            reviews_initialized="1",
            total_ratings=str(rating["totalRatings"]),
            average=str(rating["averageUserRating"]),
        )

    return messages, save


REFUND_STATUSES = {"REFUNDED", "REVERSED"}


def _fetch_subscription_info(app: config.App, inv: dict) -> dict | None:
    """Данные подписки для платежа — если это подписка и метод доступен."""
    item_code = (inv.get("order") or {}).get("itemCode")
    purchase_id = inv.get("purchaseId")
    if not (config.CHECK_SUBSCRIPTIONS and purchase_id and rustore.is_subscription(app, item_code)):
        return None
    try:
        return rustore.fetch_subscription(app, item_code, purchase_id)
    except Exception as e:
        # метод работает только для подписок через Pay SDK — это не повод терять платёж
        log.warning("Не удалось получить данные подписки %s: %s", purchase_id, e)
        return None


def check_payments(conn, app: config.App) -> CheckResult:
    """Новые платежи и возвраты за последние PAYMENTS_LOOKBACK_DAYS дней.

    Окно в несколько дней нужно, потому что API фильтрует по дате *создания*
    счёта: платёж, созданный перед полуночью, и возврат по старому платежу
    иначе не попали бы в выборку за сегодня.
    """
    today = datetime.datetime.now(config.LOCAL_TZ).date()
    dates = [(today - datetime.timedelta(days=i)).isoformat() for i in range(config.PAYMENTS_LOOKBACK_DAYS)]

    invoices: dict[int, tuple[str, dict]] = {}
    for date in dates:
        for inv in rustore.fetch_invoices(app, date):
            invoices[inv["invoiceId"]] = (date, inv)

    old_statuses = state.load_invoice_statuses(conn)
    # v2: хранятся статусы и окно в несколько дней. Со старой схемы стартуем
    # заново — без уведомлений, иначе пришли бы платежи за прошлые дни.
    is_first_run = state.get_meta(conn, "payments_v2_initialized") is None

    messages: list[str] = []
    new_count = refund_count = 0
    if not is_first_run:
        for date, inv in invoices.values():
            status = (inv.get("invoiceStatus") or "").upper()
            prev = old_statuses.get(inv["invoiceId"])
            if status == "CONFIRMED" and prev is None:
                messages.append(formatting.format_new_invoice(app, inv, _fetch_subscription_info(app, inv)))
                new_count += 1
            elif status in REFUND_STATUSES and prev not in REFUND_STATUSES:
                messages.append(formatting.format_refund(app, inv))
                refund_count += 1

    log.info(
        "Payments %s: days=%d, total=%d, new=%d, refunds=%d, first_run=%s",
        app.package, len(dates), len(invoices), new_count, refund_count, is_first_run,
    )

    def save():
        state.save_invoices(conn, [
            (invoice_id, date, (inv.get("invoiceStatus") or "").upper())
            for invoice_id, (date, inv) in invoices.items()
        ])
        state.delete_invoices_before(conn, dates[-1])
        state.save_meta(conn, payments_v2_initialized="1")

    return messages, save


# переходы, о которых не уведомляем: создание черновика разработчиком и
# автоматический перевод прошлой версии в PREVIOUS_ACTIVE при выходе новой
QUIET_VERSION_STATUSES = {"DRAFT", "DELETED_DRAFT", "PREVIOUS_ACTIVE"}


def check_versions(conn, app: config.App) -> CheckResult:
    """Смена статусов версий: модерация, одобрение, отклонение, публикация."""
    old_versions = state.load_versions(conn)
    is_first_run = state.get_meta(conn, "versions_initialized") is None

    versions = rustore.fetch_versions(app)

    messages: list[str] = []
    if not is_first_run:
        for version in versions:
            status = version.get("versionStatus")
            old_status, old_partial = old_versions.get(version["versionId"], (None, None))
            if status != old_status:
                if status not in QUIET_VERSION_STATUSES:
                    messages.append(formatting.format_version_change(version, old_status))
            elif status == "PARTIAL_ACTIVE" and version.get("partialValue") != old_partial:
                messages.append(formatting.format_partial_change(version, old_partial))

    def save():
        state.save_versions(conn, versions)
        state.save_meta(conn, versions_initialized="1")

    return messages, save


def check_access(conn, app: config.App) -> CheckResult:
    """Выдача, отзыв и изменение доступов пользователей к приложению."""
    old = state.load_developers(conn)
    is_first_run = state.get_meta(conn, "access_initialized") is None

    current: dict[tuple[str, str], str] = {}
    for dev in rustore.fetch_developers(app):
        name = " ".join(filter(None, (dev.get("firstName"), dev.get("lastName"))))
        current[(str(dev["devVkId"]), dev["role"])] = name

    messages: list[str] = []
    if not is_first_run:
        added: dict[str, set[str]] = {}
        removed: dict[str, set[str]] = {}
        for vk_id, role in current.keys() - old.keys():
            added.setdefault(vk_id, set()).add(role)
        for vk_id, role in old.keys() - current.keys():
            removed.setdefault(vk_id, set()).add(role)
        if added or removed:
            names = {vk_id: name for (vk_id, _), name in {**old, **current}.items()}
            messages.append(formatting.format_access_changes(added, removed, names))

    def save():
        state.save_developers(conn, current)
        state.save_meta(conn, access_initialized="1")

    return messages, save


def _parse_local_date(value: str | None) -> datetime.date | None:
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=config.LOCAL_TZ)
    return dt.astimezone(config.LOCAL_TZ).date()


def _collect_digest(conn, app: config.App, days: list[datetime.date], snapshot_key: str) -> tuple[dict, dict]:
    """Собирает данные для сводки за указанные дни. Возвращает (данные, новый снимок)."""
    period = set(days)
    data: dict = {}

    # платежи — по дате создания счёта; возвраты среди них считаем отдельно
    paid = refunded = 0
    paid_sum = refunded_sum = 0
    currency = "RUB"
    for day in days:
        for inv in rustore.fetch_invoices(app, day.isoformat()):
            order = inv.get("order") or {}
            amount = order.get("amountCurrent") or 0
            currency = order.get("currency") or currency
            paid += 1
            paid_sum += amount
            if (inv.get("invoiceStatus") or "").upper() in REFUND_STATUSES:
                refunded += 1
                refunded_sum += amount
    data["payments"] = (paid, paid_sum, refunded, refunded_sum, currency)

    # отзывы — из последних 100, по дате отзыва
    by_star: dict[int, int] = {}
    for review in rustore.fetch_reviews(app):
        if _parse_local_date(review.get("commentDate")) in period:
            by_star[review["appRating"]] = by_star.get(review["appRating"], 0) + 1
    data["reviews"] = by_star

    # рейтинг — сравниваем со снимком на момент прошлой такой же сводки
    rating = rustore.fetch_rating(app)
    data["rating"] = rating
    prev = state.get_meta(conn, snapshot_key)
    data["prev_rating"] = json.loads(prev) if prev else None
    snapshot = {"total": rating["totalRatings"], "average": rating["averageUserRating"]}

    if config.CHECK_VERSIONS:
        try:
            active = [v for v in rustore.fetch_versions(app) if v.get("versionStatus") in ("ACTIVE", "PARTIAL_ACTIVE")]
            data["active_versions"] = active
        except Exception as e:
            log.warning("Сводка: не удалось получить версии: %s", e)

    return data, snapshot


def _digest_check(kind: str) -> Callable:
    """Строит проверку сводки: kind — "daily" (за вчера) или "weekly" (за 7 дней до вчера)."""
    sent_key = f"digest_{kind}_sent"
    snapshot_key = f"digest_{kind}_snapshot"

    def check(conn, app: config.App) -> CheckResult:
        now = datetime.datetime.now(config.LOCAL_TZ)
        today = now.date()
        due = now.time() >= config.DIGEST_TIME and state.get_meta(conn, sent_key) != today.isoformat()
        if kind == "weekly":
            due = due and today.isoweekday() == config.DIGEST_WEEKLY_DAY
        if not due:
            return [], lambda: None

        length = 7 if kind == "weekly" else 1
        days = [today - datetime.timedelta(days=i) for i in range(length, 0, -1)]
        data, snapshot = _collect_digest(conn, app, days, snapshot_key)

        def save():
            state.save_meta(conn, **{sent_key: today.isoformat(), snapshot_key: json.dumps(snapshot)})

        return [formatting.format_digest(kind, days, data)], save

    return check


def _enabled_checks() -> list[tuple[str, Callable]]:
    checks: list[tuple[str, Callable]] = [("отзывы", check_reviews), ("платежи", check_payments)]
    if config.CHECK_VERSIONS:
        checks.append(("версии", check_versions))
    if config.CHECK_ACCESS:
        checks.append(("доступы", check_access))
    if config.DIGEST_DAILY:
        checks.append(("ежедневная сводка", _digest_check("daily")))
    if config.DIGEST_WEEKLY:
        checks.append(("еженедельная сводка", _digest_check("weekly")))
    return checks


def check_app(app: config.App):
    """Выполняет все включённые проверки одного приложения и отправляет уведомления."""
    header = formatting.app_header(app) if len(config.APPS) > 1 else ""
    conn = state.get_db(app)
    try:
        for name, check in _enabled_checks():
            try:
                messages, save = check(conn, app)
                # При ошибке notify бросит исключение — состояние проверки НЕ будет
                # сохранено, и на следующей итерации уведомления уйдут повторно.
                for msg in messages:
                    notify(header + msg)
                    time.sleep(1.0)
                save()
                conn.commit()
            except Exception:
                conn.rollback()
                log.exception("Ошибка при проверке %s: %s", app.package, name)

        state.save_meta(conn, last_check=datetime.datetime.now(config.LOCAL_TZ).isoformat())
        conn.commit()
    finally:
        conn.close()


def check_updates():
    """Проверяет все приложения."""
    for app in config.APPS:
        check_app(app)


def main():
    channels = []
    if config.TELEGRAM_ENABLED:
        channels.append("Telegram")
    if config.MATRIX_ENABLED:
        channels.append("Matrix")
    log.info(
        "RuStore monitor запущен, приложения=%s, интервал=%ds, каналы=%s, проверки=%s",
        ", ".join(app.package for app in config.APPS), config.POLL_INTERVAL, ", ".join(channels),
        ", ".join(name for name, _ in _enabled_checks()),
    )

    state.migrate_legacy_db()

    # проверяем подключение при старте
    try:
        rustore.get_rustore_token()
        log.info("Авторизация OK")
    except Exception as e:
        log.error("Ошибка авторизации: %s", e)
        sys.exit(1)

    while True:
        try:
            check_updates()
            log.info("Проверка завершена")
        except Exception:
            log.exception("Ошибка при проверке")
        time.sleep(config.POLL_INTERVAL)
