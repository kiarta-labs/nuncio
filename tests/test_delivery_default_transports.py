"""Every delivery adapter's DEFAULT transport factory (`_urllib_transport` /
`_default_smtp_factory`) -- used whenever no `transport=`/`smtp_factory=` is
injected (i.e. real production wiring via `nuncio.delivery`'s registry). Every
other delivery test in this suite injects a fake transport to isolate the
adapter's own request-shaping/response-interpretation logic from the network;
this file is the one place the actual stdlib call path
(`urllib.request.urlopen` / `smtplib.SMTP`) gets exercised, with the socket
layer itself faked out."""
import json

import nuncio.delivery.apprise as apprise_mod
import nuncio.delivery.email as email_mod
import nuncio.delivery.ntfy as ntfy_mod
import nuncio.delivery.slack as slack_mod
import nuncio.delivery.telegram as telegram_mod
import nuncio.delivery.webhook as webhook_mod


class _FakeResponse:
    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, module, response, capture=None):
    def fake_urlopen(req, timeout=10):
        if capture is not None:
            capture.append(req)
        return response
    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)


def test_apprise_default_transport_posts_and_returns_status(monkeypatch):
    captured = []
    _patch_urlopen(monkeypatch, apprise_mod, _FakeResponse(200), captured)
    a = apprise_mod.Apprise({"url": "http://apprise:8000/notify/alerts"})  # no transport injected
    assert a.send("title", "body") is True
    req = captured[0]
    assert req.full_url == "http://apprise:8000/notify/alerts"
    assert json.loads(req.data.decode()) == {"body": "body", "title": "title"}


def test_slack_default_transport_posts_and_returns_status(monkeypatch):
    captured = []
    _patch_urlopen(monkeypatch, slack_mod, _FakeResponse(200), captured)
    s = slack_mod.Slack({"webhook_url": "https://hooks.slack.com/x"})
    assert s.send("title", "body") is True
    assert captured[0].full_url == "https://hooks.slack.com/x"


def test_webhook_default_transport_posts_and_returns_status(monkeypatch):
    captured = []
    _patch_urlopen(monkeypatch, webhook_mod, _FakeResponse(200), captured)
    w = webhook_mod.Webhook({"url": "http://receiver/hook"})
    assert w.send("title", "body") is True
    assert captured[0].full_url == "http://receiver/hook"


def test_ntfy_default_transport_posts_and_returns_status(monkeypatch):
    captured = []
    _patch_urlopen(monkeypatch, ntfy_mod, _FakeResponse(200), captured)
    n = ntfy_mod.Ntfy({"url": "https://ntfy.sh", "topic": "nuncio"})
    assert n.send("title", "body") is True
    assert captured[0].full_url == "https://ntfy.sh/nuncio"


def test_telegram_default_transport_posts_and_parses_json_response(monkeypatch):
    captured = []
    _patch_urlopen(monkeypatch, telegram_mod, _FakeResponse(200, json.dumps({"ok": True}).encode()), captured)
    t = telegram_mod.Telegram({"bot_token": "tok", "chat_id": "123"})
    assert t.send("title", "body") is True
    assert "tok/sendMessage" in captured[0].full_url


def test_email_default_smtp_factory_starttls(monkeypatch):
    calls = {"starttls": 0, "sent": []}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            calls["init"] = (host, port)
        def starttls(self, context=None):
            calls["starttls"] += 1
        def send_message(self, msg):
            calls["sent"].append(msg)
        def quit(self):
            calls["quit"] = True
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(email_mod.smtplib, "SMTP", FakeSMTP)
    e = email_mod.Email({"smtp_host": "smtp.example.com", "smtp_port": 587,
                          "to": "a@example.com", "tls": "starttls"})
    assert e.send("title", "body") is True
    assert calls["starttls"] == 1
    assert calls["init"] == ("smtp.example.com", 587)


def test_email_default_smtp_factory_ssl(monkeypatch):
    calls = {}

    class FakeSMTPSSL:
        def __init__(self, host, port, timeout=None, context=None):
            calls["init"] = (host, port)
        def send_message(self, msg):
            calls.setdefault("sent", []).append(msg)
        def quit(self):
            calls["quit"] = True
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(email_mod.smtplib, "SMTP_SSL", FakeSMTPSSL)
    e = email_mod.Email({"smtp_host": "smtp.example.com", "smtp_port": 465,
                          "to": "a@example.com", "tls": "ssl"})
    assert e.send("title", "body") is True
    assert calls["init"] == ("smtp.example.com", 465)


def test_email_default_smtp_factory_no_tls(monkeypatch):
    calls = {"starttls": 0}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass
        def starttls(self, context=None):
            calls["starttls"] += 1
        def send_message(self, msg):
            pass
        def quit(self):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(email_mod.smtplib, "SMTP", FakeSMTP)
    e = email_mod.Email({"smtp_host": "smtp.example.com", "to": "a@example.com", "tls": "none"})
    assert e.send("title", "body") is True
    assert calls["starttls"] == 0  # no TLS negotiated when tls="none"
