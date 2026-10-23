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


def check_reviews(conn) -> CheckResult:
    """Новые и изменённые отзывы, «тихие» оценки без текста."""
    old_reviews = state.load_reviews(conn)
    old_ratings = state.load_ratings(conn)
    # пустой список отзывов у нового приложения — не повод считать каждый запуск первым
    is_first_run = not old_reviews and state.get_meta(conn, "reviews_initialized") is None

    rating = rustore.fetch_rating()
    reviews = rustore.fetch_reviews()

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
            log.info("Первый запуск — сохраняю начальное состояние (%d отзывов)", len(reviews))
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


def _fetch_subscription_info(inv: dict) -> dict | None:
    """Данные подписки для платежа — если это подписка и метод доступен."""
    item_code = (inv.get("order") or {}).get("itemCode")
    purchase_id = inv.get("purchaseId")
    if not (config.CHECK_SUBSCRIPTIONS and purchase_id and rustore.is_subscription(item_code)):
        return None
    try:
        return rustore.fetch_subscription(item_code, purchase_id)
    except Exception as e:
        # метод работает только для подписок через Pay SDK — это не повод терять платёж
        log.warning("Не удалось получить данные подписки %s: %s", purchase_id, e)
        return None


def check_payments(conn) -> CheckResult:
    """Новые платежи и возвраты за последние PAYMENTS_LOOKBACK_DAYS дней.

    Окно в несколько дней нужно, потому что API фильтрует по дате *создания*
    счёта: платёж, созданный перед полуночью, и возврат по старому платежу
    иначе не попали бы в выборку за сегодня.
    """
    today = datetime.datetime.now(config.LOCAL_TZ).date()
    dates = [(today - datetime.timedelta(days=i)).isoformat() for i in range(config.PAYMENTS_LOOKBACK_DAYS)]

    invoices: dict[int, tuple[str, dict]] = {}
    for date in dates:
        for inv in rustore.fetch_invoices(date):
            invoices[inv["invoiceId"]] = (date, inv)

    old_statuses = state.load_invoice_statuses(conn)
    # v2: хранятся статусы и окно в несколько дней. Со старой схемы стартуем
    # заново — без уведомлений, иначе пришли бы платежи за прошлые дни.
    is_first_run = state.get_meta(conn, "payments_v2_initialized") is None

    messages: list[str] = []
    new_count = refund_count = 0
    if not is_first_run:
        products_map = None
        for date, inv in invoices.values():
            status = (inv.get("invoiceStatus") or "").upper()
            prev = old_statuses.get(inv["invoiceId"])
            if status == "CONFIRMED" and prev is None:
                products_map = products_map or rustore.all_products_map()
                messages.append(formatting.format_new_invoice(inv, products_map, _fetch_subscription_info(inv)))
                new_count += 1
            elif status in REFUND_STATUSES and prev not in REFUND_STATUSES:
                products_map = products_map or rustore.all_products_map()
                messages.append(formatting.format_refund(inv, products_map))
                refund_count += 1

    log.info(
        "Payments: days=%d, total=%d, new=%d, refunds=%d, first_run=%s",
        len(dates), len(invoices), new_count, refund_count, is_first_run,
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


def check_versions(conn) -> CheckResult:
    """Смена статусов версий: модерация, одобрение, отклонение, публикация."""
    old_versions = state.load_versions(conn)
    is_first_run = state.get_meta(conn, "versions_initialized") is None

    versions = rustore.fetch_versions()

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


def _enabled_checks() -> list[tuple[str, Callable]]:
    checks: list[tuple[str, Callable]] = [("отзывы", check_reviews), ("платежи", check_payments)]
    if config.CHECK_VERSIONS:
        checks.append(("версии", check_versions))
    return checks


def check_updates():
    """Выполняет все включённые проверки и отправляет уведомления."""
    conn = state.get_db()
    try:
        for name, check in _enabled_checks():
            try:
                messages, save = check(conn)
                # При ошибке notify бросит исключение — состояние проверки НЕ будет
                # сохранено, и на следующей итерации уведомления уйдут повторно.
                for msg in messages:
                    notify(msg)
                    time.sleep(1.0)
                save()
                conn.commit()
            except Exception:
                conn.rollback()
                log.exception("Ошибка при проверке: %s", name)

        state.save_meta(conn, last_check=datetime.datetime.now(config.LOCAL_TZ).isoformat())
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
        "RuStore monitor запущен, пакет=%s, интервал=%ds, каналы=%s, проверки=%s",
        config.PACKAGE_NAME, config.POLL_INTERVAL, ", ".join(channels),
        ", ".join(name for name, _ in _enabled_checks()),
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
