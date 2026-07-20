"""DockerClient: real ContainerClient implementation (read-only Docker/Podman
Engine API over a unix socket or TCP endpoint)."""
import json

import pytest

from nuncio.clients.containers import (
    DockerClient,
    _UnixSocketHTTPConnection,
    demux_docker_logs,
)


def _frame(stream_type, text):
    data = text.encode()
    return bytes([stream_type, 0, 0, 0]) + len(data).to_bytes(4, "big") + data


class _FakeConn:
    """Stands in for an http.client connection: request()/getresponse()/close()."""

    def __init__(self, status, body):
        self._status = status
        self._body = body
        self.requested_path = None
        self.closed = False

    def request(self, method, path):
        self.requested_path = path
        self.method = method

    def getresponse(self):
        return self

    @property
    def status(self):
        return self._status

    def read(self, n=-1):
        return self._body

    def close(self):
        self.closed = True


def _factory(responses):
    """responses: list of (status, body) consumed in order, one per _get() call."""
    it = iter(responses)

    def factory():
        status, body = next(it)
        return _FakeConn(status, body)

    return factory


def _raising_factory(exc):
    def factory():
        raise exc
    return factory


# --- demux_docker_logs ---

def test_demux_splits_multiple_framed_chunks():
    raw = _frame(1, "line one\n") + _frame(2, "line two\n")
    text = demux_docker_logs(raw)
    assert "line one" in text
    assert "line two" in text


def test_demux_falls_back_to_plain_text_for_unframed_tty_logs():
    raw = b"just plain text, no framing header at all\n"
    assert demux_docker_logs(raw) == raw.decode()


# --- DockerClient.inspect (success path) ---

def test_inspect_returns_status_and_demuxed_logs():
    inspect_body = json.dumps({
        "State": {"Status": "running", "ExitCode": 0, "StartedAt": "2024-01-01T00:00:00Z"},
        "RestartCount": 2,
    }).encode()
    logs_body = _frame(1, "line1\n") + _frame(1, "line2\n")
    client = DockerClient("unix:///fake.sock", connection_factory=_factory([(200, inspect_body), (200, logs_body)]))
    info = client.inspect("sonarr")
    assert info["status"] == "running"
    assert info["exit_code"] == 0
    assert info["restart_count"] == 2
    assert info["started_at"] == "2024-01-01T00:00:00Z"
    assert info["logs"] == ["line1", "line2"]


def test_inspect_quotes_container_name_in_the_request_path():
    inspect_body = json.dumps({"State": {}, "RestartCount": 0}).encode()
    conn_holder = {"paths": []}

    class _Capturing(_FakeConn):
        def request(self, method, path):
            super().request(method, path)
            conn_holder["paths"].append(path)

    responses = iter([(200, inspect_body), (200, b"")])

    def factory():
        status, body = next(responses)
        return _Capturing(status, body)

    client = DockerClient("unix:///fake.sock", connection_factory=factory)
    client.inspect("my container")
    assert all("%20" in p or "+" in p for p in conn_holder["paths"])


# --- degrade-safe behavior ---

def test_inspect_returns_none_when_container_not_found():
    client = DockerClient("unix:///fake.sock", connection_factory=_factory([(404, b"")]))
    assert client.inspect("missing") is None


def test_inspect_returns_none_on_connection_exception():
    client = DockerClient("unix:///fake.sock", connection_factory=_raising_factory(ConnectionRefusedError("no")))
    assert client.inspect("sonarr") is None


def test_inspect_returns_none_on_malformed_json():
    client = DockerClient("unix:///fake.sock", connection_factory=_factory([(200, b"{not json")]))
    assert client.inspect("sonarr") is None


def test_inspect_returns_none_without_docker_host_configured():
    client = DockerClient("", connection_factory=_raising_factory(AssertionError("should not be called")))
    assert client.inspect("sonarr") is None


def test_inspect_returns_none_without_a_name():
    client = DockerClient("unix:///fake.sock", connection_factory=_raising_factory(AssertionError("should not be called")))
    assert client.inspect("") is None


def test_inspect_tolerates_missing_logs_endpoint_response():
    inspect_body = json.dumps({"State": {"Status": "exited"}, "RestartCount": 0}).encode()
    client = DockerClient("unix:///fake.sock", connection_factory=_factory([(200, inspect_body), (500, b"")]))
    info = client.inspect("sonarr")
    assert info["status"] == "exited"
    assert info["logs"] == []


# --- response size bound ---

def test_get_caps_response_body_at_max_bytes():
    # A response far larger than max_bytes gets truncated mid-structure by
    # the size cap -- the resulting invalid JSON must degrade to None, never
    # raise into the caller.
    inspect_body = json.dumps({"State": {"Status": "running", "Padding": "x" * 5000}, "RestartCount": 0}).encode()
    client = DockerClient("unix:///fake.sock", connection_factory=_factory([(200, inspect_body)]), max_bytes=50)
    assert client.inspect("sonarr") is None


# --- connection factory selection ---

def test_default_factory_uses_unix_socket_connection_for_unix_scheme():
    client = DockerClient("unix:///var/run/docker.sock")
    conn = client._open_connection()
    assert isinstance(conn, _UnixSocketHTTPConnection)


def test_default_factory_uses_tcp_connection_for_http_scheme():
    import http.client
    client = DockerClient("http://docker-proxy:2375")
    conn = client._open_connection()
    assert isinstance(conn, http.client.HTTPConnection)
    assert not isinstance(conn, _UnixSocketHTTPConnection)
