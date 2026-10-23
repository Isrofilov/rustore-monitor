"""Авторизация и запросы к API RuStore."""

import time
import base64
import logging
import datetime

import httpx
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

from . import config

log = logging.getLogger(__name__)

# ── авторизация RuStore ──

_cached_token = None
_token_expires_at = 0
_private_key = None


def _get_private_key():
    """Парсит приватный RSA-ключ один раз и кеширует."""
    global _private_key
    if _private_key is None:
        _private_key = RSA.import_key(base64.b64decode(config.PRIVATE_KEY_B64))
    return _private_key


def get_rustore_token() -> str:
    """Получает JWE-токен RuStore, кеширует до истечения TTL."""
    global _cached_token, _token_expires_at

    now = time.time()
    if _cached_token and now < _token_expires_at - 30:
        return _cached_token

    # подписываем запрос приватным RSA-ключом (SHA-512 + PKCS1 v1.5)
    private_key = _get_private_key()

    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
    message = config.KEY_ID + timestamp

    h = SHA512.new(message.encode())
    signature = base64.b64encode(pkcs1_15.new(private_key).sign(h)).decode()

    resp = httpx.post(
        config.RUSTORE_AUTH_URL,
        json={"keyId": config.KEY_ID, "timestamp": timestamp, "signature": signature},
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


def _invalidate_token():
    global _cached_token, _token_expires_at
    _cached_token = None
    _token_expires_at = 0


def _is_token_error(resp: httpx.Response) -> bool:
    """Ответ означает протухший/невалидный токен — стоит получить новый и повторить."""
    if resp.status_code == 401:
        return True
    try:
        message = (resp.json().get("message") or "").lower()
    except ValueError:
        return False
    return "expired" in message and ("jwe" in message or "token" in message)


def _rustore_get(url: str, label: str, **kwargs) -> dict:
    """Выполняет GET-запрос к API RuStore с авторизацией и проверкой ответа.

    Если токен отвергнут сервером раньше своего TTL — получает новый и
    повторяет запрос один раз.
    """
    for attempt in range(2):
        resp = httpx.get(
            url,
            headers={"Public-Token": get_rustore_token()},
            timeout=15,
            **kwargs,
        )
        if attempt == 0 and _is_token_error(resp):
            log.warning("RuStore отверг токен (%s), получаю новый", label)
            _invalidate_token()
            continue
        break

    resp.raise_for_status()
    data = resp.json()
    if data.get("code") != "OK":
        raise RuntimeError(f"Ошибка {label}: {data.get('message')}")
    return data["body"]


def fetch_rating(app: config.App) -> dict:
    """Получает статистику оценок приложения."""
    return _rustore_get(
        f"{config.RUSTORE_API_BASE}/{app.package}/comment/statistic",
        "получения рейтинга",
    )


def fetch_reviews(app: config.App, size: int = 100) -> list[dict]:
    """Получает список последних отзывов."""
    return _rustore_get(
        f"{config.RUSTORE_API_BASE}/{app.package}/comment",
        "получения отзывов",
        params={"size": size},
    )


def fetch_products(app: config.App) -> list[dict]:
    """Получает список продуктов (разовые покупки)."""
    body = _rustore_get(
        f"{config.RUSTORE_PAYMENTS_BASE}/{app.app_id}/catalog/products",
        "получения продуктов",
    )
    return body.get("elements", [])


def fetch_subscriptions(app: config.App) -> list[dict]:
    """Получает список подписок."""
    body = _rustore_get(
        f"{config.RUSTORE_PAYMENTS_BASE}/{app.app_id}/catalog/subscriptions",
        "получения подписок",
    )
    return body.get("elements", [])


# appId → (productId → название, набор productId подписок)
_catalogs: dict[str, tuple[dict[str, str], set[str]]] = {}


def all_products_map(app: config.App) -> dict[str, str]:
    """Возвращает кешированный словарь productId → name. Загружает при первом вызове."""
    if app.app_id not in _catalogs:
        _refresh_products_cache(app)
    return _catalogs[app.app_id][0]


def _refresh_products_cache(app: config.App):
    """Перезагружает словарь продуктов и подписок из API."""
    products = fetch_products(app)
    subscriptions = fetch_subscriptions(app)
    names = {item["productId"]: item["name"] for item in products + subscriptions}
    _catalogs[app.app_id] = (names, {item["productId"] for item in subscriptions})
    log.info("Кеш продуктов %s обновлён, %d записей", app.package, len(names))


def is_subscription(app: config.App, item_code: str | None) -> bool:
    """Является ли продукт подпиской (по каталогу подписок)."""
    if not item_code:
        return False
    all_products_map(app)
    return item_code in _catalogs[app.app_id][1]


def resolve_product_name(app: config.App, order: dict) -> str:
    """Определяет название продукта по itemCode. При промахе кеша — перезагружает."""
    code = order.get("itemCode")
    if not code:
        return order.get("visualName") or "—"
    products_map = all_products_map(app)
    if code in products_map:
        return products_map[code]
    # ключ не найден — перезагружаем кеш
    _refresh_products_cache(app)
    return _catalogs[app.app_id][0].get(code) or order.get("visualName") or "—"


INVOICE_STATUSES = ("confirmed", "refunded", "reversed")


def fetch_invoices(app: config.App, date: str) -> list[dict]:
    """Получает успешные и возвращённые платежи, созданные в указанную дату (все страницы)."""
    invoices: list[dict] = []
    page = 0
    while True:
        body = _rustore_get(
            f"{config.RUSTORE_PAYMENTS_BASE}/{app.app_id}/invoices",
            "получения платежей",
            params={
                "invoiceStatuses": INVOICE_STATUSES,
                "invoiceDate": date,
                "pageNumber": page,
                "pageSize": 500,
            },
        )
        invoices.extend(body.get("content") or [])
        page += 1
        if page >= (body.get("totalPages") or 0):
            return invoices


def fetch_subscription(app: config.App, subscription_id: str, purchase_id: str) -> dict:
    """Получает данные подписки пользователя (v5, только для подписок через Pay SDK)."""
    return _rustore_get(
        f"{config.RUSTORE_PUBLIC_BASE}/v5/subscription/"
        f"{app.package}/{subscription_id}/{purchase_id}",
        "получения данных подписки",
    )


def fetch_versions(app: config.App) -> list[dict]:
    """Получает последние версии приложения (релизные и альфа) со статусами."""
    body = _rustore_get(
        f"{config.RUSTORE_API_BASE}/{app.package}/version",
        "получения статусов версий",
        params={"filterTestingType": "ALL", "page": 0, "size": 100},
    )
    return body.get("content") or []


def fetch_developers(app: config.App) -> list[dict]:
    """Получает всех пользователей с доступом к приложению и их роли (все страницы)."""
    developers: list[dict] = []
    params: dict = {"pageSize": 100}
    while True:
        body = _rustore_get(
            f"{config.RUSTORE_API_BASE}/{app.package}/developer",
            "получения доступов",
            params=params,
        )
        developers.extend(body.get("content") or [])
        token = body.get("pageToken")
        if not token:
            return developers
        params = {"pageSize": 100, "pageToken": token}
