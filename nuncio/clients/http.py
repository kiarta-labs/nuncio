"""Small stdlib-only HTTP helpers shared by the real collector-client
implementations (`nuncio/clients/logs.py`, `containers.py`, `metrics.py`).

Every request made through here is a plain GET or POST against a read-only
query endpoint -- never a write/exec/mutate call -- and is bounded on two
axes: a socket-level timeout (so a stalled endpoint can't hang the calling
collector thread past its budget) and a maximum response size (so a
misbehaving endpoint can't be used to exhaust memory). Callers always pass
an explicit timeout; nothing here defaults to "no timeout".

This module raises on failure (network error, non-2xx, oversized body, bad
JSON) rather than swallowing it -- the individual client classes are the
layer that catches broadly and degrades to an empty result, per the
protocol contract in `nuncio/clients/__init__.py`.
"""
import base64
import json
import urllib.request

DEFAULT_MAX_BYTES = 2_000_000  # generous cap for a JSON search/query response


def basic_or_bearer_auth(user, token):
    """The common auth-header shape across the supported backends: HTTP
    Basic when a username is configured (OpenObserve-style service
    accounts), a bearer token when only a token is set (Loki/Prometheus
    behind an auth proxy), or no auth header at all for an open endpoint."""
    if user:
        cred = base64.b64encode(f"{user}:{token or ''}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {cred}"}
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def request_json(method, url, headers=None, payload=None, timeout=4.0, max_bytes=DEFAULT_MAX_BYTES):
    """Issue one GET/POST, return the parsed JSON body (or None for an empty
    body). `payload`, if given, is JSON-encoded as the request body and a
    `Content-Type: application/json` header is added. Raises on any
    failure -- see module docstring."""
    hdrs = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ValueError(f"response exceeded {max_bytes} byte cap")
    if not body:
        return None
    return json.loads(body.decode("utf-8", errors="replace"))
