"""Apprise delivery adapter. A single best-effort send attempt; retry is
handled separately by `delivery/retrying.py`, which wraps every adapter.

Speaks Apprise's `/notify/<key>` webhook contract: `{"body", "title"}`.
Apprise returns 204 when the configured key has NO destination configured —
nothing was actually pushed — so a 204 counts as FAILURE here (never trust it
as success, or a mis-keyed config silently black-holes every alert).
"""
import json
import urllib.request

from nuncio.delivery import DeliveryAdapter, register, require_http_url


def _urllib_transport(url, payload, timeout=10):
    require_http_url(url)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


@register
class Apprise(DeliveryAdapter):
    name = "apprise"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        self.url = cfg.get("url") or None
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.url:
            return False
        payload = {"body": body, "title": title}
        status = self._transport(self.url, payload, self.timeout)
        # 204 = Apprise accepted but had NO destination -> nothing pushed;
        # treat as failure so a mis-keyed config can't black-hole alerts.
        return 200 <= status < 300 and status != 204
