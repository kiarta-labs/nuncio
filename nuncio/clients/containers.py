"""Real `ContainerClient` implementation: read-only Docker/Podman Engine
API access.

Only ever issues GET requests against `/containers/<name>/json` (inspect)
and `/containers/<name>/logs` (tail) -- never a write, exec, attach, or
lifecycle (start/stop/restart/remove) endpoint. `NUNCIO_DOCKER_HOST` accepts
either a unix socket (`unix:///var/run/docker.sock`) or a TCP endpoint
(`http://docker-proxy:2375`).

A raw Docker socket is root-equivalent to whoever can reach it (it can
create privileged containers, mount the host filesystem, etc.) -- mounting
it directly into Nuncio works, but a read-only socket-proxy in front of it
(one that only forwards GET requests, e.g. a `docker-socket-proxy` with
`CONTAINERS=1` and every write flag left off) is strongly recommended for
anything beyond a small single-operator deployment, since Nuncio itself only
ever needs GET."""
import http.client
import json
import logging
import socket
from urllib.parse import quote, urlsplit

log = logging.getLogger("nuncio.clients.containers")

_UNIX_PREFIX = "unix://"


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """`http.client.HTTPConnection` over an `AF_UNIX` socket. Stdlib's
    `HTTPConnection` only knows how to dial `AF_INET`/`AF_INET6`, so
    `connect()` is overridden to open the unix socket path instead; every
    other method (request framing, response parsing, timeout handling) is
    inherited unchanged."""

    def __init__(self, socket_path, timeout=4.0):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def demux_docker_logs(raw):
    """Docker's non-TTY container logs are multiplexed: each chunk is
    prefixed with an 8-byte binary frame header (1 stream-type byte, 3
    reserved bytes, then a 4-byte big-endian length). Demux it. A TTY
    container's logs are NOT framed at all -- if the bytes don't parse as a
    complete run of valid frames, fall back to treating them as plain text
    rather than dropping the logs."""
    out = bytearray()
    i = 0
    n = len(raw)
    framed_any = False
    while i + 8 <= n:
        stream_type = raw[i]
        if stream_type not in (0, 1, 2):
            break
        length = int.from_bytes(raw[i + 4:i + 8], "big")
        chunk_start = i + 8
        chunk_end = chunk_start + length
        if chunk_end > n:
            break
        out.extend(raw[chunk_start:chunk_end])
        i = chunk_end
        framed_any = True
    if not framed_any or i != n:
        return raw.decode("utf-8", errors="replace")
    return bytes(out).decode("utf-8", errors="replace")


class DockerClient:
    def __init__(self, docker_host, timeout=4.0, max_log_lines=200, max_bytes=200_000,
                 connection_factory=None):
        self._docker_host = docker_host or ""
        self._timeout = timeout
        self._max_log_lines = max_log_lines
        self._max_bytes = max_bytes
        # Injectable for tests; defaults to actually dialing NUNCIO_DOCKER_HOST.
        self._connection_factory = connection_factory or self._open_connection

    def _open_connection(self):
        if self._docker_host.startswith(_UNIX_PREFIX):
            path = self._docker_host[len(_UNIX_PREFIX):]
            return _UnixSocketHTTPConnection(path, timeout=self._timeout)
        parts = urlsplit(self._docker_host)
        if parts.scheme == "https":
            return http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=self._timeout)
        return http.client.HTTPConnection(parts.hostname or "localhost", parts.port or 2375,
                                           timeout=self._timeout)

    def _get(self, path):
        """GET path over a fresh connection; returns the raw response body
        (bytes, capped) on 200, or None on any other status."""
        conn = self._connection_factory()
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read(self._max_bytes + 1)
            status = resp.status
        finally:
            conn.close()
        if status != 200:
            return None
        return body[: self._max_bytes]

    def inspect(self, name):
        if not self._docker_host or not name:
            return None
        try:
            return self._inspect(name)
        except Exception as e:
            log.debug("docker inspect failed for %r: %r", name, e)
            return None

    def _inspect(self, name):
        safe = quote(name, safe="")
        raw = self._get(f"/containers/{safe}/json")
        if raw is None:
            return None
        data = json.loads(raw.decode("utf-8", errors="replace"))
        state = data.get("State") or {}
        logs_raw = self._get(
            f"/containers/{safe}/logs?stdout=1&stderr=1&tail={self._max_log_lines}"
        )
        logs = []
        if logs_raw:
            text = demux_docker_logs(logs_raw)
            logs = [ln for ln in text.splitlines() if ln.strip()][-self._max_log_lines:]
        return {
            "status": state.get("Status"),
            "restart_count": data.get("RestartCount"),
            "exit_code": state.get("ExitCode"),
            "started_at": state.get("StartedAt"),
            "logs": logs,
        }
