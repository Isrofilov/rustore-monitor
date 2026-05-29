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
"""

import os
import datetime
from pathlib import Path

# ── эндпоинты RuStore ──

RUSTORE_AUTH_URL = "https://public-api.rustore.ru/public/auth"
RUSTORE_API_BASE = "https://public-api.rustore.ru/public/v1/application"
RUSTORE_PAYMENTS_BASE = "https://public-api.rustore.ru/public/applications"

DB_FILE = Path("/data/state.db")  # база состояния внутри Docker-тома

# ── RuStore ──

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

# ── включённые каналы уведомлений ──

TELEGRAM_ENABLED = bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
MATRIX_ENABLED = bool(MATRIX_HOMESERVER and MATRIX_ACCESS_TOKEN and MATRIX_ROOM_ID)

if not (TELEGRAM_ENABLED or MATRIX_ENABLED):
    raise SystemExit(
        "Не настроен ни один канал уведомлений. Задайте Telegram "
        "(TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID) и/или Matrix "
        "(MATRIX_HOMESERVER + MATRIX_ACCESS_TOKEN + MATRIX_ROOM_ID)."
    )
