"""ntfy delivery adapter — plain POST to a ntfy topic, stdlib only.
`cfg`: `url` (e.g. https://ntfy.sh), `topic`, optional `token` (Bearer auth
for a private/self-hosted ntfy instance)."""
import urllib.request
from email.header import Header

from nuncio.delivery import DeliveryAdapter, register
from nuncio.envelope import SEVERITY_PRIORITY as _PRIORITY


def _urllib_transport(url, body_bytes, headers, timeout=10):
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


@register
class Ntfy(DeliveryAdapter):
    name = "ntfy"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        base = (cfg.get("url") or "").rstrip("/")
        topic = cfg.get("topic") or ""
        self.url = f"{base}/{topic}" if base and topic else None
        self.token = cfg.get("token") or None
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.url:
            return False
        # HTTP header values can't contain newlines; strip that BEFORE any
        # encoding (a header-injection guard, not an ASCII concern).
        safe_title = (title or "alert").replace("\n", " ").replace("\r", " ")
        try:
            safe_title.encode("ascii")
            title_header = safe_title
        except UnicodeEncodeError:
            # Non-ASCII (e.g. the severity emoji) would otherwise be silently
            # dropped by an ascii-only header encode -- RFC 2047-encode
            # instead so it survives; ntfy decodes RFC 2047 titles.
            title_header = Header(safe_title, "utf-8").encode()
        headers = {
            "Title": title_header,
            "Priority": _PRIORITY.get(severity, "3"),
            "Content-Type": "text/plain; charset=utf-8",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        status = self._transport(self.url, body.encode("utf-8"), headers, self.timeout)
        return 200 <= status < 300
