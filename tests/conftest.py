import os
import tempfile

# config читает окружение при импорте — задаём до импорта пакета
os.environ.update(
    RUSTORE_KEY_ID="1",
    RUSTORE_PRIVATE_KEY="x",
    RUSTORE_PACKAGE_NAME="com.example.app",
    RUSTORE_APP_ID="100",
    TELEGRAM_BOT_TOKEN="token",
    TELEGRAM_CHAT_ID="1",
    DATA_DIR=tempfile.mkdtemp(),
)
os.environ.pop("RUSTORE_APPS", None)

import pytest  # noqa: E402

from rustore_monitor import config, monitor, rustore  # noqa: E402

EMPTY_RATINGS = {"amountFive": 0, "amountFour": 0, "amountThree": 0, "amountTwo": 0, "amountOne": 0}


class FakeApi:
    """Подменяет методы RuStore API данными из атрибутов."""

    def __init__(self):
        self.ratings = dict(EMPTY_RATINGS)
        self.reviews: list[dict] = []
        self.invoices: dict[str, list[dict]] = {}
        self.versions: list[dict] = []
        self.developers: list[dict] = []
        self.products: list[dict] = []
        self.subscriptions: list[dict] = []
        self.subscription: dict | None = None

    def rating(self, app):
        total = sum(self.ratings.values())
        avg = sum(star * self.ratings[key] for key, star in
                  [("amountFive", 5), ("amountFour", 4), ("amountThree", 3), ("amountTwo", 2), ("amountOne", 1)])
        return {"ratings": dict(self.ratings), "totalRatings": total, "averageUserRating": avg / total if total else 0}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    return config.APPS[0]


@pytest.fixture
def api(monkeypatch):
    fake = FakeApi()
    monkeypatch.setattr(rustore, "fetch_rating", fake.rating)
    monkeypatch.setattr(rustore, "fetch_reviews", lambda app, size=100: fake.reviews)
    monkeypatch.setattr(rustore, "fetch_invoices", lambda app, date: fake.invoices.get(date, []))
    monkeypatch.setattr(rustore, "fetch_versions", lambda app: fake.versions)
    monkeypatch.setattr(rustore, "fetch_developers", lambda app: fake.developers)
    monkeypatch.setattr(rustore, "fetch_products", lambda app: fake.products)
    monkeypatch.setattr(rustore, "fetch_subscriptions", lambda app: fake.subscriptions)
    monkeypatch.setattr(rustore, "fetch_subscription", lambda app, sub_id, purchase_id: fake.subscription)
    monkeypatch.setattr(rustore, "_catalogs", {})
    return fake


@pytest.fixture
def sent(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr(monitor, "notify", messages.append)
    monkeypatch.setattr(monitor.time, "sleep", lambda s: None)
    monkeypatch.setattr(monitor, "_failures", {})
    return messages
