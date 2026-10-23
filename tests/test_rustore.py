import httpx

from rustore_monitor import rustore


class Resp:
    def __init__(self, status, data):
        self.status_code = status
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=None)


def test_expired_token_is_refreshed(monkeypatch, app):
    tokens = iter(["old", "new"])
    monkeypatch.setattr(rustore, "get_rustore_token", lambda: rustore._cached_token or next(tokens))
    monkeypatch.setattr(rustore, "_cached_token", None)

    def get(url, headers, **kwargs):
        if headers["Public-Token"] == "old":
            return Resp(401, {"code": "ERROR", "message": "Jwe token is expired"})
        return Resp(200, {"code": "OK", "body": {"ok": True}})

    monkeypatch.setattr(rustore.httpx, "get", get)
    assert rustore._rustore_get("https://x", "теста") == {"ok": True}


def test_invoices_pagination(monkeypatch, app):
    monkeypatch.setattr(rustore, "get_rustore_token", lambda: "t")
    pages = []

    def get(url, headers, params, **kwargs):
        pages.append(params["pageNumber"])
        body = {"content": [{"invoiceId": params["pageNumber"]}], "totalPages": 3}
        return Resp(200, {"code": "OK", "body": body})

    monkeypatch.setattr(rustore.httpx, "get", get)
    assert [inv["invoiceId"] for inv in rustore.fetch_invoices(app, "2026-01-01")] == [0, 1, 2]
    assert pages == [0, 1, 2]


def test_developers_pagination(monkeypatch, app):
    monkeypatch.setattr(rustore, "get_rustore_token", lambda: "t")

    def get(url, headers, params, **kwargs):
        if params.get("pageToken") == "next":
            body = {"content": [{"devVkId": "2"}], "pageToken": None}
        else:
            body = {"content": [{"devVkId": "1"}], "pageToken": "next"}
        return Resp(200, {"code": "OK", "body": body})

    monkeypatch.setattr(rustore.httpx, "get", get)
    assert [d["devVkId"] for d in rustore.fetch_developers(app)] == ["1", "2"]
