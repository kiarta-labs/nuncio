"""Slack incoming-webhook delivery adapter, stdlib only. `cfg`: `webhook_url`."""
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
class Slack(DeliveryAdapter):
    name = "slack"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        self.url = cfg.get("webhook_url") or None
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.url:
            return False
        text = f"*{title}*\n{body}" if title else body
        status = self._transport(self.url, {"text": text}, self.timeout)
        return 200 <= status < 300
