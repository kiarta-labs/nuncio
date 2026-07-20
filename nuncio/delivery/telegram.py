"""Telegram delivery adapter — `sendMessage`, stdlib only. `cfg`: `bot_token`,
`chat_id`. Chunks the body into <=4096-char
Telegram messages (Telegram's hard per-message limit); title is prefixed only
onto the first chunk."""
import json
import urllib.request

from nuncio.delivery import DeliveryAdapter, register, require_http_url

_MAX_CHARS = 4096


def _urllib_transport(url, payload, timeout=10):
    require_http_url(url)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode())


def _chunks(text, size):
    return [text[i:i + size] for i in range(0, len(text), size)] or [""]


@register
class Telegram(DeliveryAdapter):
    name = "telegram"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        self.bot_token = cfg.get("bot_token") or None
        self.chat_id = cfg.get("chat_id") or None
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.bot_token or not self.chat_id:
            return False
        full = f"{title}\n\n{body}" if title else body
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        sent_any = False
        # A failure partway through a multi-chunk body returns False here,
        # and the whole send is retried by Retrying from chunk 1 again --
        # the already-delivered earlier chunk(s) land a second time on a
        # retry. Accepted under the at-least-once delivery contract (never
        # losing a chunk beats never duplicating one).
        for chunk in _chunks(full, _MAX_CHARS):
            payload = {"chat_id": self.chat_id, "text": chunk}
            try:
                status, resp = self._transport(url, payload, self.timeout)
            except Exception:
                return False
            if not (200 <= status < 300 and resp.get("ok", True)):
                return False
            sent_any = True
        return sent_any
