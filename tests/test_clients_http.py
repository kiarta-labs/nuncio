"""Shared HTTP transport helpers used by the real collector-client backends."""
import json

import pytest

from nuncio.clients.http import basic_or_bearer_auth, request_json


# --- basic_or_bearer_auth ---

def test_basic_auth_used_when_user_is_set():
    headers = basic_or_bearer_auth("alice", "secret")
    assert headers["Authorization"].startswith("Basic ")


def test_bearer_auth_used_when_only_token_is_set():
    headers = basic_or_bearer_auth("", "sk-abc123")
    assert headers["Authorization"] == "Bearer sk-abc123"


def test_no_auth_header_when_nothing_configured():
    assert basic_or_bearer_auth("", "") == {}


def test_basic_auth_is_correctly_base64_encoded():
    import base64
    headers = basic_or_bearer_auth("alice", "secret")
    token = headers["Authorization"].split(" ", 1)[1]
    assert base64.b64decode(token).decode() == "alice:secret"


# --- request_json: uses urllib under the hood, timeout + size bounded ---

class _FakeResponse:
    def __init__(self, body, status=200):
        self._body = body
        self.status = status

    def read(self, n=-1):
        return self._body[:n] if n and n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_request_json_get_parses_response_body(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["timeout"] = timeout
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = request_json("GET", "http://example/query", timeout=2.5)
    assert result == {"ok": True}
    assert captured["method"] == "GET"
    assert captured["timeout"] == 2.5


def test_request_json_post_sends_json_payload(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode())
        captured["content_type"] = req.get_header("Content-type")
        return _FakeResponse(json.dumps({"status": "success"}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = request_json("POST", "http://example/search", payload={"q": "x"}, timeout=2.0)
    assert result == {"status": "success"}
    assert captured["body"] == {"q": "x"}
    assert captured["content_type"] == "application/json"


def test_request_json_raises_on_oversized_response(monkeypatch):
    big = b"x" * 100

    def fake_urlopen(req, timeout=None):
        return _FakeResponse(big)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(ValueError):
        request_json("GET", "http://example/query", timeout=1.0, max_bytes=10)


def test_request_json_returns_none_for_empty_body(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(b"")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    assert request_json("GET", "http://example/query", timeout=1.0) is None


def test_request_json_propagates_connection_errors(monkeypatch):
    import urllib.error

    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(urllib.error.URLError):
        request_json("GET", "http://example/query", timeout=1.0)


# --- URL scheme allowlist: only http/https are legitimate collector-endpoint
# schemes. A `file://` or `gopher://` URL reaching here (misconfiguration or
# an operator-controlled value) must be rejected before any network call is
# attempted -- never silently opened. ---

def test_request_json_rejects_file_scheme_without_calling_urlopen(monkeypatch):
    def boom(req, timeout=None):
        raise AssertionError("urlopen must never be called for a non-http(s) scheme")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(ValueError, match="unsupported URL scheme"):
        request_json("GET", "file:///etc/passwd", timeout=1.0)


def test_request_json_rejects_gopher_scheme_without_calling_urlopen(monkeypatch):
    def boom(req, timeout=None):
        raise AssertionError("urlopen must never be called for a non-http(s) scheme")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(ValueError, match="unsupported URL scheme"):
        request_json("GET", "gopher://example/x", timeout=1.0)


def test_request_json_rejects_file_scheme_case_insensitively(monkeypatch):
    def boom(req, timeout=None):
        raise AssertionError("urlopen must never be called for a non-http(s) scheme")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(ValueError, match="unsupported URL scheme"):
        request_json("GET", "FILE:///etc/passwd", timeout=1.0)


def test_request_json_allows_http_scheme_through_to_urlopen(monkeypatch):
    called = {}

    def fake_urlopen(req, timeout=None):
        called["hit"] = True
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = request_json("GET", "http://example/query", timeout=1.0)
    assert result == {"ok": True}
    assert called.get("hit") is True


def test_request_json_allows_https_scheme_through_to_urlopen(monkeypatch):
    called = {}

    def fake_urlopen(req, timeout=None):
        called["hit"] = True
        return _FakeResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    result = request_json("GET", "https://example/query", timeout=1.0)
    assert result == {"ok": True}
    assert called.get("hit") is True


# --- adversarial: a genuinely hung endpoint must not block past its timeout.
# This is the real socket path (no monkeypatched urlopen) against a live TCP
# server that accepts the connection and then never writes a byte back --
# the failure mode a stalled/overloaded log or metrics backend would produce
# in the field. request_json must fail with a socket timeout, not hang. ---

def test_request_json_never_blocks_past_its_timeout_against_a_hung_server():
    import socket
    import threading
    import time

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept_and_hang():
        server.settimeout(5.0)
        try:
            conn, _ = server.accept()
        except OSError:
            return
        # Accept the connection but never send a response, until the test
        # is done -- simulates a wedged/overloaded backend.
        stop.wait(5.0)
        conn.close()

    t = threading.Thread(target=accept_and_hang, daemon=True)
    t.start()
    try:
        start = time.monotonic()
        with pytest.raises(Exception):
            request_json("GET", f"http://127.0.0.1:{port}/query", timeout=0.5)
        elapsed = time.monotonic() - start
        # Generous slack over the 0.5s socket timeout -- this asserts "did
        # not hang indefinitely", not a tight latency bound.
        assert elapsed < 3.0
    finally:
        stop.set()
        server.close()
        t.join(timeout=2.0)
