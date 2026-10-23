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


def fetch_rating() -> dict:
    """Получает статистику оценок приложения."""
    return _rustore_get(
        f"{config.RUSTORE_API_BASE}/{config.PACKAGE_NAME}/comment/statistic",
        "получения рейтинга",
    )


def fetch_reviews(size: int = 100) -> list[dict]:
    """Получает список последних отзывов."""
    return _rustore_get(
        f"{config.RUSTORE_API_BASE}/{config.PACKAGE_NAME}/comment",
        "получения отзывов",
        params={"size": size},
    )


def fetch_products() -> list[dict]:
    """Получает список продуктов (разовые покупки)."""
    body = _rustore_get(
        f"{config.RUSTORE_PAYMENTS_BASE}/{config.APP_ID}/catalog/products",
        "получения продуктов",
    )
    return body.get("elements", [])


def fetch_subscriptions() -> list[dict]:
    """Получает список подписок."""
    body = _rustore_get(
        f"{config.RUSTORE_PAYMENTS_BASE}/{config.APP_ID}/catalog/subscriptions",
        "получения подписок",
    )
    return body.get("elements", [])


_products_cache: dict[str, str] = {}


def all_products_map() -> dict[str, str]:
    """Возвращает кешированный словарь productId → name. Загружает при первом вызове."""
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


def fetch_invoices(date: str) -> list[dict]:
    """Получает подтверждённые платежи за указанную дату."""
    body = _rustore_get(
        f"{config.RUSTORE_PAYMENTS_BASE}/{config.APP_ID}/invoices",
        "получения платежей",
        params={"invoiceStatuses": "confirmed", "invoiceDate": date},
    )
    return body.get("content", [])
