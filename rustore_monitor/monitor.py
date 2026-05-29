"""Основной цикл мониторинга RuStore."""

import sys
import time
import logging
import datetime

from . import config, state, rustore, formatting
from .notifiers import notify

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


def check_updates():
    """Проверяет новые отзывы, изменения оценок и платежи, отправляет уведомления."""
    conn = state.get_db()
    try:
        old_comment_ids = state.load_comment_ids(conn)
        old_ratings = state.load_ratings(conn)
        old_edited = state.load_edited_ids(conn)

        rating = rustore.fetch_rating()
        reviews = rustore.fetch_reviews()

        current_comment_ids = {r["commentId"] for r in reviews}
        current_edited = {r["commentId"] for r in reviews if r.get("edited")}

        messages = []

        # новые отзывы (пропускаем при первом запуске)
        new_ids = current_comment_ids - old_comment_ids
        if old_comment_ids:
            for review in reviews:
                if review["commentId"] in new_ids:
                    messages.append(formatting.format_new_review(review, rating))

        # отредактированные отзывы
        newly_edited = current_edited - old_edited
        if old_comment_ids:
            for review in reviews:
                if review["commentId"] in newly_edited and review["commentId"] not in new_ids:
                    messages.append(formatting.format_edited_review(review, rating))

        # «тихие» оценки без текста — обнаруживаем по изменению распределения.
        # Вклад новых отзывов из diff'а вычитаем, чтобы не дублировать уведомления.
        if old_ratings:
            changes: dict[int, int] = {}
            for key, star in formatting.RATING_NAMES.items():
                diff = rating["ratings"].get(key, 0) - old_ratings.get(key, 0)
                if diff != 0:
                    changes[star] = diff
            for review in reviews:
                if review["commentId"] in new_ids:
                    star = review["appRating"]
                    if star in changes:
                        changes[star] -= 1
                        if changes[star] == 0:
                            del changes[star]
            if changes:
                messages.append(formatting.format_silent_ratings(changes, rating))

        # ── проверка платежей ──
        today = datetime.datetime.now(config.LOCAL_TZ).strftime("%Y-%m-%d")
        current_invoice_ids: set[int] = set()

        try:
            invoices = rustore.fetch_invoices(today)

            old_invoice_ids = state.load_invoice_ids(conn, today)
            current_invoice_ids = {inv["invoiceId"] for inv in invoices}

            new_invoices = rustore.detect_new_invoices(invoices, old_invoice_ids)

            is_first_run = state.get_meta(conn, "payments_initialized") is None

            log.info(
                "Payments: total=%d, old=%d, new=%d, first_run=%s",
                len(invoices),
                len(old_invoice_ids),
                len(new_invoices),
                is_first_run,
            )

            # отправляем ТОЛЬКО если это не первый запуск
            if not is_first_run and new_invoices:
                products_map = rustore.all_products_map()

                for inv in new_invoices:
                    msg = formatting.format_new_invoice(inv, products_map)
                    messages.append(msg)

            # помечаем, что инициализация была
            if is_first_run:
                state.save_meta(conn, payments_initialized="1")

        except Exception:
            log.exception("Ошибка при проверке платежей")

        # отправляем уведомления во включённые каналы.
        # При ошибке notify бросит исключение — состояние НЕ будет сохранено,
        # и на следующей итерации уведомления уйдут повторно (без потерь).
        for msg in messages:
            notify(msg)
            time.sleep(1.0)

        if not old_comment_ids:
            log.info("Первый запуск — сохраняю начальное состояние (%d отзывов)", len(reviews))

        # сохраняем текущее состояние для следующей проверки
        state.save_reviews(conn, current_comment_ids, current_edited)
        state.save_invoices(conn, current_invoice_ids, today)
        state.save_ratings(conn, rating["ratings"])
        state.save_meta(
            conn,
            total_ratings=str(rating["totalRatings"]),
            average=str(rating["averageUserRating"]),
            last_check=datetime.datetime.now(config.LOCAL_TZ).isoformat(),
        )
        conn.commit()
    finally:
        conn.close()


def main():
    channels = []
    if config.TELEGRAM_ENABLED:
        channels.append("Telegram")
    if config.MATRIX_ENABLED:
        channels.append("Matrix")
    log.info(
        "RuStore monitor запущен, пакет=%s, интервал=%ds, каналы=%s",
        config.PACKAGE_NAME, config.POLL_INTERVAL, ", ".join(channels),
    )

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
