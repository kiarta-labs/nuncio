"""Apprise delivery adapter. A single best-effort send attempt; retry is
handled separately by `delivery/retrying.py`, which wraps every adapter.

Speaks Apprise's `/notify/<key>` webhook contract: `{"body", "title"}`.
Apprise returns 204 when the configured key has NO destination configured —
nothing was actually pushed — so a 204 counts as FAILURE here (never trust it
as success, or a mis-keyed config silently black-holes every alert).
"""
import json
import socket
import urllib.error
import urllib.request

from nuncio.delivery import DeliveryAdapter, SendTimeout, register, require_http_url


def _urllib_transport(url, payload, timeout=10):
    require_http_url(url)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def _is_timeout(exc):
    if isinstance(exc, socket.timeout):  # TimeoutError alias, 3.10+
        return True
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, (socket.timeout, TimeoutError))
    return False


@register
class Apprise(DeliveryAdapter):
    name = "apprise"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        self.url = cfg.get("url") or None
        self._transport = transport or _urllib_transport
        self.timeout = cfg.get("timeout", timeout)

    def send(self, title, body, severity="unknown", **kw):
        if not self.url:
            return False
        payload = {"body": body, "title": title}
        try:
            status = self._transport(self.url, payload, self.timeout)
        except Exception as e:
            # A timeout is reclassified to a typed, distinct exception --
            # see SendTimeout's docstring for why Retrying must not treat it
            # like an ordinary transient failure. Anything else (connection
            # refused, DNS failure, HTTP error status) propagates unchanged.
            if _is_timeout(e):
                raise SendTimeout(str(e)) from e
            raise
        # 204 = Apprise accepted but had NO destination -> nothing pushed;
        # treat as failure so a mis-keyed config can't black-hole alerts.
        return 200 <= status < 300 and status != 204
