"""Slack incoming-webhook delivery adapter."""
from nuncio.delivery.slack import Slack


class Transport:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    def __call__(self, url, payload, timeout=10):
        self.calls.append((url, payload, timeout))
        return self.status


def test_send_success():
    t = Transport(200)
    s = Slack({"webhook_url": "https://hooks.slack.com/x"}, transport=t)
    assert s.send("title", "body") is True
    url, payload, timeout = t.calls[0]
    assert "title" in payload["text"] and "body" in payload["text"]


def test_no_url_fails_closed():
    t = Transport(200)
    s = Slack({}, transport=t)
    assert s.send("t", "b") is False
    assert t.calls == []


def test_failure_status_returns_false():
    t = Transport(500)
    s = Slack({"webhook_url": "https://hooks.slack.com/x"}, transport=t)
    assert s.send("t", "b") is False
