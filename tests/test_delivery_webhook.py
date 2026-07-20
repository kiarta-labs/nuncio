"""Generic webhook delivery adapter."""
import json

import pytest

from nuncio.delivery.webhook import Webhook


class Transport:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    def __call__(self, url, data_bytes, headers, timeout=10):
        self.calls.append((url, data_bytes, headers, timeout))
        return self.status


def test_default_template_sends_valid_json():
    t = Transport(200)
    w = Webhook({"url": "http://x"}, transport=t)
    assert w.send("the title", "the body", "critical") is True
    _, data, headers, _ = t.calls[0]
    parsed = json.loads(data.decode())
    assert parsed == {"title": "the title", "body": "the body", "severity": "critical"}
    assert headers["Content-Type"] == "application/json"


def test_custom_template_placeholders_substituted():
    t = Transport(200)
    w = Webhook({"url": "http://x", "template": '{"text": "{title}\\n{body}"}'}, transport=t)
    w.send("T", "B")
    parsed = json.loads(t.calls[0][1].decode())
    assert parsed == {"text": "T\nB"}


def test_custom_headers_merged_in():
    t = Transport(200)
    w = Webhook({"url": "http://x", "headers": {"X-Custom": "1"}}, transport=t)
    w.send("t", "b")
    assert t.calls[0][2]["X-Custom"] == "1"


def test_template_producing_invalid_json_fails_closed():
    t = Transport(200)
    w = Webhook({"url": "http://x", "template": "{title} not json at all"}, transport=t)
    assert w.send("t", "b") is False
    assert t.calls == []


def test_special_characters_are_json_escaped():
    t = Transport(200)
    w = Webhook({"url": "http://x"}, transport=t)
    w.send('title with "quotes"', "body\nwith\nnewlines")
    parsed = json.loads(t.calls[0][1].decode())
    assert parsed["title"] == 'title with "quotes"'
    assert parsed["body"] == "body\nwith\nnewlines"


def test_no_url_fails_closed():
    t = Transport(200)
    w = Webhook({}, transport=t)
    assert w.send("t", "b") is False
    assert t.calls == []


def test_failure_status_returns_false():
    t = Transport(500)
    w = Webhook({"url": "http://x"}, transport=t)
    assert w.send("t", "b") is False


def test_send_rejects_non_http_scheme(monkeypatch):
    # Operator-config-only exposure (consistency with clients/http.py's
    # scheme allowlist), but a misconfigured file:// URL must never even
    # reach urlopen.
    def fail_urlopen(*a, **kw):
        pytest.fail("urlopen should not be reached for a non-http scheme")

    monkeypatch.setattr("nuncio.delivery.webhook.urllib.request.urlopen", fail_urlopen)
    w = Webhook({"url": "file:///tmp/x"})  # real default transport, not the fake
    try:
        assert not w.send("t", "b")
    except ValueError:
        pass  # raise is caught by Retrying / existing failure handling
