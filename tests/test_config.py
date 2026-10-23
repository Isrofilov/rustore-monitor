import pytest

from rustore_monitor import config


def test_parse_apps(monkeypatch):
    monkeypatch.setenv("RUSTORE_APPS", "com.a:1:Приложение A, com.b:2")
    apps = config._parse_apps()
    assert [(a.package, a.app_id, a.label) for a in apps] == [
        ("com.a", "1", "Приложение A"),
        ("com.b", "2", "com.b"),
    ]


def test_parse_apps_falls_back_to_single_app(monkeypatch):
    monkeypatch.delenv("RUSTORE_APPS", raising=False)
    monkeypatch.setenv("RUSTORE_PACKAGE_NAME", "com.single")
    monkeypatch.setenv("RUSTORE_APP_ID", "7")
    assert config._parse_apps() == [config.App("com.single", "7", "com.single")]


@pytest.mark.parametrize("value", ["com.a", "com.a:abc", "com.a:1,com.a:2"])
def test_parse_apps_rejects_invalid(monkeypatch, value):
    monkeypatch.setenv("RUSTORE_APPS", value)
    with pytest.raises(SystemExit):
        config._parse_apps()
