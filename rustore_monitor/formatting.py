"""Форматирование HTML-сообщений для уведомлений."""

import html

from .rustore import resolve_product_name

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
    user = html.escape(review.get("userName") or "—")
    text = html.escape(review.get("commentText") or "")
    version_raw = review.get("appVersionName")
    version = f"  •  v{html.escape(version_raw)}" if version_raw else ""
    edited = "  (ред.)" if review.get("edited") else ""
    return (
        f"📝 <b>Новый отзыв в RuStore</b>\n\n"
        f"{stars}  •  {user}{version}{edited}\n"
        f"«{text}»\n\n"
        f"{format_stats(rating)}"
    )


def format_edited_review(review: dict, rating: dict) -> str:
    stars = "⭐" * review["appRating"]
    user = html.escape(review.get("userName") or "—")
    text = html.escape(review.get("commentText") or "")
    version_raw = review.get("appVersionName")
    version = f"  •  v{html.escape(version_raw)}" if version_raw else ""
    return (
        f"✏️ <b>Отзыв изменён</b>\n\n"
        f"{stars}  •  {user}{version}\n"
        f"«{text}»\n\n"
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
    payment = inv.get("paymentInfo", {})

    amount = order.get("amountCurrent", 0) // 100
    currency = order.get("currency", "RUB")
    if currency == "RUB":
        currency = "₽"

    visual_name = html.escape(order.get("visualName") or "—")
    name = html.escape(resolve_product_name(order, products_map))

    pay_date = html.escape(payment.get("paymentDate") or inv.get("invoiceDate") or "")
    method = html.escape(format_payment_method(payment))

    lines = [
        "💰 <b>Новый платёж</b>",
        "",
        f"<b>{visual_name}</b>",
        f"<b>Продукт:</b> {name}",
        f"<b>Сумма:</b> {amount} {currency}",
        "",
        f"<b>Дата:</b> {pay_date}",
    ]

    if method:
        lines.append(f"<b>Способ оплаты:</b> {method}")

    return "\n".join(lines)
