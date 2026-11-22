"""Отправка уведомлений в Telegram и/или Matrix.

Сообщения формируются в виде HTML с переводами строк через ``\\n``
(совместимо с Telegram parse_mode=HTML). Для Matrix HTML кладётся в
``formatted_body`` (с заменой ``\\n`` на ``<br>``), а в ``body`` —
текстовая версия без тегов.

При исчерпании ретраев отправка в канал бросает исключение. Уведомления
проверок идут через очередь исходящих (``send_to`` по одному каналу,
доставка отмечается по каналам отдельно); ``notify`` — для служебных
сообщений, которые не стоят повторной доставки.
"""

import re
import html
import time
import logging
import itertools
from urllib.parse import quote

import httpx

from . import config

log = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")

# счётчик для уникальных Matrix transaction id
_txn_counter = itertools.count()


def _html_to_plain(text: str) -> str:
    """Убирает HTML-теги и декодирует сущности для текстовой версии сообщения."""
    return html.unescape(_TAG_RE.sub("", text))


def tg_send(text: str):
    """Отправляет HTML-сообщение в Telegram-чат с ретраями."""
    payload = {"chat_id": config.TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    if config.TELEGRAM_THREAD_ID:
        payload["message_thread_id"] = int(config.TELEGRAM_THREAD_ID)
    url = f"https://{config.TELEGRAM_DOMAIN}/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"

    last_error = None
    for attempt in range(3):
        try:
            resp = httpx.post(url, json=payload, timeout=15)
        except httpx.RequestError as e:
            last_error = e
            log.warning("Telegram send failed (attempt %d): %s", attempt + 1, e)
            time.sleep(2 ** attempt)
            continue

        if resp.is_success:
            return

        # rate-limit: Telegram сообщает retry_after в секундах
        if resp.status_code == 429:
            retry_after = resp.json().get("parameters", {}).get("retry_after", 1)
            log.warning("Telegram 429, retry after %ds", retry_after)
            time.sleep(retry_after)
            continue

        last_error = RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
        log.warning("Telegram send error (attempt %d): %s", attempt + 1, last_error)
        time.sleep(2 ** attempt)

    raise RuntimeError(f"Не удалось отправить в Telegram после 3 попыток: {last_error}")


def matrix_send(text: str, txn_id: str | None = None):
    """Отправляет сообщение в Matrix-комнату через Client-Server API с ретраями.

    ``txn_id`` — идемпотентный ключ: все попытки идут с одним id, и если ответ
    потерялся, сервер распознает повтор и не создаст дубликат. Без него id
    генерируется один раз на вызов.
    """
    body = _html_to_plain(text)
    formatted_body = text.replace("\n", "<br>")
    payload = {
        "msgtype": "m.text",
        "body": body,
        "format": "org.matrix.custom.html",
        "formatted_body": formatted_body,
    }
    headers = {"Authorization": f"Bearer {config.MATRIX_ACCESS_TOKEN}"}
    room = quote(config.MATRIX_ROOM_ID, safe="")

    # transaction id уникален для сообщения, но общий для его ретраев:
    # сервер дедуплицирует повторы с тем же id в рамках access token
    if txn_id is None:
        txn_id = f"{int(time.time() * 1000)}-{next(_txn_counter)}"
    url = (
        f"{config.MATRIX_HOMESERVER}/_matrix/client/v3/rooms/"
        f"{room}/send/m.room.message/{quote(txn_id, safe='')}"
    )

    last_error = None
    for attempt in range(3):
        try:
            resp = httpx.put(url, json=payload, headers=headers, timeout=15)
        except httpx.RequestError as e:
            last_error = e
            log.warning("Matrix send failed (attempt %d): %s", attempt + 1, e)
            time.sleep(2 ** attempt)
            continue

        if resp.is_success:
            return

        # rate-limit: Matrix сообщает retry_after_ms в теле ответа
        if resp.status_code == 429:
            retry_after_ms = resp.json().get("retry_after_ms", 1000)
            log.warning("Matrix 429, retry after %dms", retry_after_ms)
            time.sleep(retry_after_ms / 1000)
            continue

        last_error = RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
        log.warning("Matrix send error (attempt %d): %s", attempt + 1, last_error)
        time.sleep(2 ** attempt)

    raise RuntimeError(f"Не удалось отправить в Matrix после 3 попыток: {last_error}")


def send_to(channel: str, text: str, msg_key: str | None = None):
    """Отправка в один конкретный канал (для очереди исходящих)."""
    if channel == "telegram":
        tg_send(text)
    elif channel == "matrix":
        matrix_send(text, txn_id=msg_key)
    else:
        raise ValueError(f"Неизвестный канал: {channel}")


def notify(text: str):
    """Отправляет сообщение во все включённые каналы (без очереди).

    Если хотя бы один канал не смог доставить сообщение после ретраев —
    бросает исключение после попытки во все каналы.
    """
    errors = []

    if config.TELEGRAM_ENABLED:
        try:
            tg_send(text)
        except Exception as e:
            errors.append(e)

    if config.MATRIX_ENABLED:
        try:
            matrix_send(text)
        except Exception as e:
            errors.append(e)

    if errors:
        raise RuntimeError("; ".join(str(e) for e in errors))
