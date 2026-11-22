import httpx

from rustore_monitor import config, notifiers


def test_matrix_retries_reuse_txn_id(monkeypatch):
    monkeypatch.setattr(config, "MATRIX_HOMESERVER", "https://matrix.example")
    monkeypatch.setattr(config, "MATRIX_ROOM_ID", "!room:example")
    monkeypatch.setattr(config, "MATRIX_ACCESS_TOKEN", "t")
    monkeypatch.setattr(notifiers.time, "sleep", lambda s: None)

    urls: list[str] = []

    def put(url, **kwargs):
        urls.append(url)
        if len(urls) < 3:
            raise httpx.ConnectError("ответ потерялся")
        return httpx.Response(200, json={"event_id": "$1"})

    monkeypatch.setattr(notifiers.httpx, "put", put)
    notifiers.matrix_send("<b>привет</b>", txn_id="rustore-monitor:com.a:1:2026-11-22T10:00:00+03:00")

    assert len(urls) == 3 and len(set(urls)) == 1
    assert urls[0].endswith("/rustore-monitor%3Acom.a%3A1%3A2026-11-22T10%3A00%3A00%2B03%3A00")
