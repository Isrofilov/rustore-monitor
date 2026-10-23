import datetime

from rustore_monitor import config, formatting


def test_format_amount():
    assert formatting.format_amount(12990) == "129,90 ₽"
    assert formatting.format_amount(100) == "1 ₽"
    assert formatting.format_amount(123456700) == "1 234 567 ₽"
    assert formatting.format_amount(-500, "USD") == "-5 USD"


def test_format_datetime_converts_to_local_tz(monkeypatch):
    monkeypatch.setattr(config, "LOCAL_TZ", datetime.timezone(datetime.timedelta(hours=3)))
    assert formatting.format_datetime("2024-10-24T11:31:33+00:00") == "24.10.2024 14:31"
    assert formatting.format_datetime("1694431707000") == "11.09.2023 14:28"
    assert formatting.format_datetime("не дата") == "не дата"
    assert formatting.format_datetime(None) == ""


def test_subscription_lines():
    first = formatting._subscription_lines({"orderId": "3352", "autoRenewing": True})
    assert first == ["<b>Подписка:</b> первая оплата"]
    renewal = formatting._subscription_lines({"orderId": "3352..1", "autoRenewing": False, "paymentState": 2})
    assert renewal[0] == "<b>Подписка:</b> продление, платёж №2"
    assert "<b>Пробный период</b>" in renewal
    assert "<b>Автопродление:</b> отключено" in renewal


def test_long_review_is_truncated():
    review = {"appRating": 5, "commentText": "a" * 5000}
    rating = {"ratings": dict.fromkeys(formatting.RATING_NAMES, 0), "averageUserRating": 0, "totalRatings": 0}
    assert len(formatting.format_new_review(review, rating)) < 4096


def test_user_text_is_escaped():
    review = {"appRating": 1, "commentText": "<b>x</b> & y", "userName": "<script>"}
    rating = {"ratings": dict.fromkeys(formatting.RATING_NAMES, 0), "averageUserRating": 0, "totalRatings": 0}
    text = formatting.format_new_review(review, rating)
    assert "&lt;b&gt;x&lt;/b&gt; &amp; y" in text
    assert "&lt;script&gt;" in text


def test_review_shows_version_code_and_device():
    review = {
        "appRating": 4, "commentText": "ok", "userName": "U", "appVersionName": "1.4", "appVersionCode": 42,
        "deviceInfo": {"device": "Samsung", "model": "SM-G973F", "osVersion": "Android 12"},
    }
    rating = {"ratings": dict.fromkeys(formatting.RATING_NAMES, 0), "averageUserRating": 0, "totalRatings": 0}
    text = formatting.format_new_review(review, rating)
    assert "v1.4 (42)" in text
    assert "📲 Samsung SM-G973F  •  Android 12" in text
    assert "📲" not in formatting.format_new_review(dict(review, deviceInfo=None), rating)
