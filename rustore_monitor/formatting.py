"""Форматирование HTML-сообщений для уведомлений."""

import html
import datetime

from . import config
from .rustore import resolve_product_name

RATING_NAMES = {
    "amountFive": 5,
    "amountFour": 4,
    "amountThree": 3,
    "amountTwo": 2,
    "amountOne": 1,
}

# длинные отзывы обрезаем, чтобы сообщение влезло в лимит Telegram (4096 символов)
MAX_REVIEW_LEN = 1500


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


def _review_text(text: str | None) -> str:
    text = text or ""
    if len(text) > MAX_REVIEW_LEN:
        text = text[:MAX_REVIEW_LEN].rstrip() + "…"
    return html.escape(text)


def _review_author(review: dict) -> str:
    user = html.escape(review.get("userName") or "—")
    version_raw = review.get("appVersionName")
    version = f"  •  v{html.escape(version_raw)}" if version_raw else ""
    return f"{user}{version}"


def format_new_review(review: dict, rating: dict) -> str:
    stars = "⭐" * review["appRating"]
    edited = "  (ред.)" if review.get("edited") else ""
    return (
        f"📝 <b>Новый отзыв в RuStore</b>\n\n"
        f"{stars}  •  {_review_author(review)}{edited}\n"
        f"«{_review_text(review.get('commentText'))}»\n\n"
        f"{format_stats(rating)}"
    )


def format_edited_review(review: dict, old_rating: int, old_text: str, rating: dict) -> str:
    new_rating = review["appRating"]
    new_text = review.get("commentText") or ""
    lines = ["✏️ <b>Отзыв изменён</b>", "", _review_author(review)]

    if old_rating != new_rating:
        lines.append(f"Оценка: {'⭐' * old_rating} → {'⭐' * new_rating}")
    else:
        lines.append("⭐" * new_rating)

    if old_text != new_text:
        lines.append(f"Было: «{_review_text(old_text)}»")
        lines.append(f"Стало: «{_review_text(new_text)}»")
    else:
        lines.append(f"«{_review_text(new_text)}»")

    return "\n".join(lines) + f"\n\n{format_stats(rating)}"


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


# ── платежи ──


def format_datetime(value: str | int | None) -> str:
    """ISO-строку или миллисекунды с эпохи → «ДД.ММ.ГГГГ ЧЧ:ММ» в локальном часовом поясе."""
    if value in (None, ""):
        return ""
    try:
        if isinstance(value, int) or str(value).isdigit():
            dt = datetime.datetime.fromtimestamp(int(value) / 1000, datetime.timezone.utc)
        else:
            dt = datetime.datetime.fromisoformat(str(value))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return str(value)
    return dt.astimezone(config.LOCAL_TZ).strftime("%d.%m.%Y %H:%M")


def format_amount(minor_units: int | float, currency: str = "RUB") -> str:
    """Сумма в копейках → «1 299,90 ₽» (копейки — только если они есть)."""
    minor = int(minor_units or 0)
    sign = "-" if minor < 0 else ""
    major, cents = divmod(abs(minor), 100)
    major_str = f"{major:,}".replace(",", " ")
    amount = f"{sign}{major_str},{cents:02d}" if cents else f"{sign}{major_str}"
    symbol = "₽" if currency == "RUB" else html.escape(currency or "")
    return f"{amount} {symbol}".strip()


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


def format_new_invoice(inv: dict, products_map: dict) -> str:
    order = inv.get("order", {})
    payment = inv.get("paymentInfo") or {}

    amount = format_amount(order.get("amountCurrent", 0), order.get("currency", "RUB"))
    visual_name = html.escape(order.get("visualName") or "—")
    name = html.escape(resolve_product_name(order, products_map))

    pay_date = html.escape(format_datetime(payment.get("paymentDate") or inv.get("invoiceDate")))
    method = html.escape(format_payment_method(payment))

    lines = [
        "💰 <b>Новый платёж</b>",
        "",
        f"<b>{visual_name}</b>",
        f"<b>Продукт:</b> {name}",
        f"<b>Сумма:</b> {amount}",
    ]

    lines += ["", f"<b>Дата:</b> {pay_date}"]

    if method:
        lines.append(f"<b>Способ оплаты:</b> {method}")

    return "\n".join(lines)


def format_refund(inv: dict, products_map: dict) -> str:
    order = inv.get("order", {})
    status = (inv.get("invoiceStatus") or "").upper()

    title = "↩️ <b>Возврат средств</b>" if status == "REFUNDED" else "↩️ <b>Холд отменён, деньги возвращены</b>"
    amount = format_amount(order.get("amountCurrent", 0), order.get("currency", "RUB"))
    name = html.escape(resolve_product_name(order, products_map))

    lines = [
        title,
        "",
        f"<b>Продукт:</b> {name}",
        f"<b>Сумма:</b> {amount}",
        f"<b>Счёт:</b> №{inv.get('invoiceId')} от {html.escape(format_datetime(inv.get('invoiceDate')))}",
    ]
    refund_date = format_datetime(inv.get("refundDate"))
    if refund_date:
        lines.append(f"<b>Дата возврата:</b> {html.escape(refund_date)}")
    return "\n".join(lines)
