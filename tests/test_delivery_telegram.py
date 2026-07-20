"""Telegram delivery adapter."""
import pytest

from nuncio.delivery.telegram import Telegram, _chunks, _urllib_transport


class Transport:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, url, payload, timeout=10):
        self.calls.append((url, payload, timeout))
        return self.results[len(self.calls) - 1]


def test_send_success():
    t = Transport([(200, {"ok": True})])
    tg = Telegram({"bot_token": "tok", "chat_id": "123"}, transport=t)
    assert tg.send("title", "body") is True
    url, payload, timeout = t.calls[0]
    assert "tok/sendMessage" in url
    assert payload["chat_id"] == "123"
    assert "title" in payload["text"] and "body" in payload["text"]


def test_missing_config_fails_closed():
    t = Transport([(200, {"ok": True})])
    tg = Telegram({}, transport=t)
    assert tg.send("t", "b") is False
    assert t.calls == []


def test_api_error_returns_false():
    t = Transport([(200, {"ok": False, "description": "blocked"})])
    tg = Telegram({"bot_token": "tok", "chat_id": "1"}, transport=t)
    assert tg.send("t", "b") is False


def test_http_failure_returns_false():
    t = Transport([(403, {"ok": False})])
    tg = Telegram({"bot_token": "tok", "chat_id": "1"}, transport=t)
    assert tg.send("t", "b") is False


def test_transport_exception_returns_false_not_raise():
    def boom(url, payload, timeout=10):
        raise ConnectionError("network down")
    tg = Telegram({"bot_token": "tok", "chat_id": "1"}, transport=boom)
    assert tg.send("t", "b") is False


def test_long_body_is_chunked_under_4096():
    assert _chunks("a" * 10000, 4096) == ["a" * 4096, "a" * 4096, "a" * (10000 - 8192)]


def test_long_message_sends_multiple_chunks():
    t = Transport([(200, {"ok": True})] * 3)
    tg = Telegram({"bot_token": "tok", "chat_id": "1"}, transport=t)
    assert tg.send("title", "x" * 9000) is True
    assert len(t.calls) >= 2


def test_send_rejects_non_http_scheme(monkeypatch):
    # Telegram's send() always builds an https://api.telegram.org URL
    # internally (never operator-config-controlled), so this exercises the
    # shared _urllib_transport helper directly -- defense-in-depth,
    # consistent with the other adapters' transport helpers.
    def fail_urlopen(*a, **kw):
        pytest.fail("urlopen should not be reached for a non-http scheme")

    monkeypatch.setattr("nuncio.delivery.telegram.urllib.request.urlopen", fail_urlopen)
    with pytest.raises(ValueError):
        _urllib_transport("file:///tmp/x", {"chat_id": "1", "text": "hi"}, timeout=10)
