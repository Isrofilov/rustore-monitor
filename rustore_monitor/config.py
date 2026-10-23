"""
Конфигурация из переменных окружения.

Должен быть настроен хотя бы один канал уведомлений — Telegram или Matrix.

Переменные окружения:
    RUSTORE_KEY_ID       — id ключа API
    RUSTORE_PRIVATE_KEY  — приватный ключ в формате base64
    RUSTORE_PACKAGE_NAME — имя пакета приложения (например, com.example.app)
    RUSTORE_APP_ID       — числовой id приложения из консоли RuStore
    TELEGRAM_DOMAIN      — домен Telegram API (по умолчанию api.telegram.org)
    TELEGRAM_BOT_TOKEN   — токен Telegram-бота (для включения Telegram)
    TELEGRAM_CHAT_ID     — id чата для уведомлений (для включения Telegram)
    TELEGRAM_THREAD_ID   — id темы в супергруппе (опционально)
    MATRIX_HOMESERVER    — URL домашнего сервера Matrix (для включения Matrix)
    MATRIX_ACCESS_TOKEN  — токен доступа Matrix (для включения Matrix)
    MATRIX_ROOM_ID       — id комнаты для уведомлений (для включения Matrix)
    POLL_INTERVAL        — интервал опроса в секундах (по умолчанию 300)
    TZ_OFFSET            — смещение часового пояса в часах (по умолчанию +3, МСК)
    PAYMENTS_LOOKBACK_DAYS — за сколько последних дней проверять платежи и возвраты (по умолчанию 7)
    CHECK_VERSIONS       — отслеживать статусы версий (по умолчанию 1)
    CHECK_SUBSCRIPTIONS  — дополнять платежи по подпискам данными подписки (по умолчанию 1)
"""

import os
import datetime
from pathlib import Path

# ── эндпоинты RuStore ──

RUSTORE_AUTH_URL = "https://public-api.rustore.ru/public/auth"
RUSTORE_API_BASE = "https://public-api.rustore.ru/public/v1/application"
RUSTORE_PAYMENTS_BASE = "https://public-api.rustore.ru/public/applications"

RUSTORE_PUBLIC_BASE = "https://public-api.rustore.ru/public"

DB_FILE = Path("/data/state.db")  # база состояния внутри Docker-тома

# ── RuStore ──

_REQUIRED = ("RUSTORE_KEY_ID", "RUSTORE_PRIVATE_KEY", "RUSTORE_PACKAGE_NAME", "RUSTORE_APP_ID")
_missing = [name for name in _REQUIRED if not os.environ.get(name)]
if _missing:
    raise SystemExit(f"Не заданы обязательные переменные окружения: {', '.join(_missing)}")

KEY_ID = os.environ["RUSTORE_KEY_ID"]
PRIVATE_KEY_B64 = os.environ["RUSTORE_PRIVATE_KEY"]
PACKAGE_NAME = os.environ["RUSTORE_PACKAGE_NAME"]
APP_ID = os.environ["RUSTORE_APP_ID"]

# ── Telegram (опционально) ──

TELEGRAM_DOMAIN = os.environ.get("TELEGRAM_DOMAIN") or "api.telegram.org"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
TELEGRAM_THREAD_ID = os.environ.get("TELEGRAM_THREAD_ID")

# ── Matrix (опционально) ──

MATRIX_HOMESERVER = (os.environ.get("MATRIX_HOMESERVER") or "").rstrip("/")
MATRIX_ACCESS_TOKEN = os.environ.get("MATRIX_ACCESS_TOKEN")
MATRIX_ROOM_ID = os.environ.get("MATRIX_ROOM_ID")

# ── общее ──

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL") or "300")
TZ_OFFSET = int(os.environ.get("TZ_OFFSET") or "3")
LOCAL_TZ = datetime.timezone(datetime.timedelta(hours=TZ_OFFSET))
PAYMENTS_LOOKBACK_DAYS = max(1, int(os.environ.get("PAYMENTS_LOOKBACK_DAYS") or "7"))


def _flag(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if not value:
        return default
    return value.strip().lower() not in ("0", "false", "no", "off")


CHECK_VERSIONS = _flag("CHECK_VERSIONS")
CHECK_SUBSCRIPTIONS = _flag("CHECK_SUBSCRIPTIONS")
