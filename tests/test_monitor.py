import datetime

from rustore_monitor import config, monitor


def review(cid, stars, text="текст"):
    return {"commentId": cid, "appRating": stars, "commentText": text, "userName": "User"}


def invoice(iid, status, item="coins"):
    return {
        "invoiceId": iid,
        "invoiceStatus": status,
        "invoiceDate": "2026-01-01T10:00:00+03:00",
        "purchaseId": f"p{iid}",
        "order": {"amountCurrent": 9900, "currency": "RUB", "itemCode": item, "visualName": "Покупка"},
        "paymentInfo": {},
    }


def today():
    return datetime.datetime.now(config.LOCAL_TZ).date()


# ── отзывы ──


def test_first_run_is_silent_then_new_review_notifies(app, api, sent):
    api.reviews = [review(1, 5)]
    api.ratings["amountFive"] = 1
    monitor.check_app(app)
    assert sent == []

    api.reviews.append(review(2, 1, "плохо"))
    api.ratings["amountOne"] = 1
    monitor.check_app(app)
    assert len(sent) == 1
    assert "Новый отзыв" in sent[0] and "плохо" in sent[0]


def test_first_review_of_empty_app_is_not_lost(app, api, sent):
    monitor.check_app(app)
    api.reviews = [review(1, 4)]
    api.ratings["amountFour"] = 1
    monitor.check_app(app)
    assert len(sent) == 1 and "Новый отзыв" in sent[0]


def test_repeated_edits_are_detected_without_silent_rating(app, api, sent):
    api.reviews = [review(1, 2, "плохо")]
    api.ratings["amountTwo"] = 1
    monitor.check_app(app)

    for stars, text in [(4, "лучше"), (5, "отлично")]:
        old_key = {2: "amountTwo", 4: "amountFour"}[api.reviews[0]["appRating"]]
        api.ratings[old_key] -= 1
        api.ratings[{4: "amountFour", 5: "amountFive"}[stars]] += 1
        api.reviews = [dict(review(1, stars, text), edited=True)]
        monitor.check_app(app)

    assert len(sent) == 2
    assert all("Отзыв изменён" in m for m in sent)
    assert "«лучше»" in sent[1] and "«отлично»" in sent[1]


def test_silent_rating(app, api, sent):
    monitor.check_app(app)
    api.ratings["amountThree"] = 2
    monitor.check_app(app)
    assert len(sent) == 1 and "+2 × 3⭐" in sent[0]


# ── платежи ──


def test_new_payment_and_refund(app, api, sent):
    day = today().isoformat()
    api.products = [{"productId": "coins", "name": "Монеты"}]
    api.invoices = {day: [invoice(1, "confirmed")]}
    monitor.check_app(app)
    assert sent == []

    api.invoices = {day: [invoice(1, "refunded"), invoice(2, "confirmed")]}
    monitor.check_app(app)
    assert len(sent) == 2
    assert "Возврат" in sent[0] and "Монеты" in sent[0]
    assert "Новый платёж" in sent[1] and "99 ₽" in sent[1]

    monitor.check_app(app)
    assert len(sent) == 2  # повторно не уведомляем


def test_payment_from_yesterday_is_found(app, api, sent):
    monitor.check_app(app)
    yesterday = (today() - datetime.timedelta(days=1)).isoformat()
    api.invoices = {yesterday: [invoice(5, "confirmed")]}
    monitor.check_app(app)
    assert len(sent) == 1 and "Новый платёж" in sent[0]


def test_subscription_details(app, api, sent):
    api.subscriptions = [{"productId": "premium", "name": "Премиум"}]
    api.subscription = {"orderId": "10..1", "expiryTimeMillis": "1797083457000", "autoRenewing": True}
    monitor.check_app(app)
    api.invoices = {today().isoformat(): [invoice(7, "confirmed", item="premium")]}
    monitor.check_app(app)
    assert "продление, платёж №2" in sent[0] and "Действует до" in sent[0]


def test_failed_notification_is_retried(app, api, monkeypatch):
    monitor.check_app(app)
    api.invoices = {today().isoformat(): [invoice(1, "confirmed")]}

    def broken(text):
        raise RuntimeError("Telegram недоступен")

    monkeypatch.setattr(monitor, "notify", broken)
    monkeypatch.setattr(monitor.time, "sleep", lambda s: None)
    monitor.check_app(app)

    sent = []
    monkeypatch.setattr(monitor, "notify", sent.append)
    monitor.check_app(app)
    assert len(sent) == 1 and "Новый платёж" in sent[0]


# ── версии и доступы ──


def test_version_transitions(app, api, sent):
    api.versions = [{"versionId": 1, "versionStatus": "DRAFT", "versionName": "2.0", "versionCode": 20}]
    monitor.check_app(app)
    for status in ["MODERATION", "REJECTED_BY_MODERATOR"]:
        api.versions = [dict(api.versions[0], versionStatus=status)]
        monitor.check_app(app)
    api.versions = [dict(api.versions[0], versionStatus="PARTIAL_ACTIVE", partialValue=10)]
    monitor.check_app(app)
    api.versions = [dict(api.versions[0], partialValue=50)]
    monitor.check_app(app)

    assert len(sent) == 4
    assert "на модерации" in sent[0]
    assert "отклонена модератором" in sent[1]
    assert "10%" in sent[2]
    assert "10% → 50%" in sent[3]


def test_access_changes(app, api, sent):
    api.developers = [
        {"devVkId": "1", "role": "OWNER", "firstName": "Иван", "lastName": "Иванов"},
        {"devVkId": "2", "role": "DEV", "firstName": "Пётр", "lastName": "Петров"},
    ]
    monitor.check_app(app)
    api.developers = [
        {"devVkId": "1", "role": "OWNER", "firstName": "Иван", "lastName": "Иванов"},
        {"devVkId": "2", "role": "ADMIN", "firstName": "Пётр", "lastName": "Петров"},
        {"devVkId": "3", "role": "SUPPORT", "firstName": "Анна", "lastName": ""},
    ]
    monitor.check_app(app)
    assert len(sent) == 1
    assert "Пётр Петров (VK ID 2): разработчик → администратор" in sent[0]
    assert "➕ Анна (VK ID 3): специалист поддержки" in sent[0]


# ── сводки и сбои ──


def test_daily_digest_sent_once(app, api, sent, monkeypatch):
    monkeypatch.setattr(config, "DIGEST_DAILY", True)
    monkeypatch.setattr(config, "DIGEST_TIME", datetime.time(0, 0))
    yesterday = (today() - datetime.timedelta(days=1)).isoformat()
    api.invoices = {yesterday: [invoice(1, "confirmed"), invoice(2, "refunded")]}
    monitor.check_app(app)
    monitor.check_app(app)
    digests = [m for m in sent if "Сводка за день" in m]
    assert len(digests) == 1
    assert "Платежей:</b> 2 на 198 ₽" in digests[0]
    assert "возвращено:</b> 1 на 99 ₽" in digests[0]


def test_alert_after_repeated_failures(app, api, sent, monkeypatch):
    monkeypatch.setattr(config, "ALERT_AFTER_FAILURES", 2)

    def broken(app):
        raise RuntimeError("Forbidden")

    monkeypatch.setattr(monitor.rustore, "fetch_versions", broken)
    for _ in range(3):
        monitor.check_app(app)
    monkeypatch.setattr(monitor.rustore, "fetch_versions", lambda app: [])
    monitor.check_app(app)

    assert len(sent) == 2
    assert "«версии» не проходит" in sent[0] and "Forbidden" in sent[0]
    assert "«версии» снова работает" in sent[1]


def test_multiple_apps_have_separate_state_and_header(tmp_path, api, sent, monkeypatch):
    apps = [config.App("com.a", "1", "Первое"), config.App("com.b", "2", "Второе")]
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "APPS", apps)
    monitor.check_updates()
    api.reviews = [review(1, 5)]
    api.ratings["amountFive"] = 1
    monitor.check_updates()
    assert len(sent) == 2
    assert sent[0].startswith("📱 <b>Первое</b>") and sent[1].startswith("📱 <b>Второе</b>")
    assert (tmp_path / "state-com.a.db").exists() and (tmp_path / "state-com.b.db").exists()
