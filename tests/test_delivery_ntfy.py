"""ntfy delivery adapter."""
from email.header import decode_header

from nuncio.delivery.ntfy import Ntfy


class Transport:
    def __init__(self, status=200):
        self.status = status
        self.calls = []

    def __call__(self, url, body_bytes, headers, timeout=10):
        self.calls.append((url, body_bytes, headers, timeout))
        return self.status


def test_send_success_builds_topic_url():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "my-alerts"}, transport=t)
    assert n.send("title", "body") is True
    url, body, headers, timeout = t.calls[0]
    assert url == "https://ntfy.sh/my-alerts"
    assert body == b"body"
    assert headers["Title"] == "title"


def test_severity_maps_to_priority():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "x"}, transport=t)
    n.send("t", "b", "critical")
    assert t.calls[0][2]["Priority"] == "5"


def test_token_sets_authorization_header():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "x", "token": "abc"}, transport=t)
    n.send("t", "b")
    assert t.calls[0][2]["Authorization"] == "Bearer abc"


def test_no_topic_configured_fails_closed():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh"}, transport=t)
    assert n.send("t", "b") is False
    assert t.calls == []


def test_failure_status_returns_false():
    t = Transport(500)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "x"}, transport=t)
    assert n.send("t", "b") is False


# --- non-ASCII (severity emoji) titles must survive, RFC 2047-encoded ---

def test_non_ascii_title_is_rfc2047_encoded_and_round_trips():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "x"}, transport=t)
    title = "❗ host01/db — db is down"  # ❗ host01/db — db is down
    n.send(title, "b")
    header_value = t.calls[0][2]["Title"]
    decoded_parts = decode_header(header_value)
    decoded = "".join(
        part.decode(enc or "ascii") if isinstance(part, bytes) else part
        for part, enc in decoded_parts
    )
    assert decoded == title


def test_ascii_title_stays_a_plain_unencoded_string():
    t = Transport(200)
    n = Ntfy({"url": "https://ntfy.sh", "topic": "x"}, transport=t)
    n.send("plain ascii title", "b")
    header_value = t.calls[0][2]["Title"]
    assert header_value == "plain ascii title"
    assert "=?" not in header_value  # not RFC 2047-encoded
