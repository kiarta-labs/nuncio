"""Generic webhook delivery adapter — the escape hatch for any JSON-webhook
receiver that doesn't have its own built-in adapter (Discord, Mattermost,
Gotify, ...). `cfg`: `url`, optional `headers` (dict), optional `template` (a
string with `{title}`/`{body}`/`{severity}`/`{headline}`/`{summary}`/
`{host}`/`{service}` placeholders controlling the payload shape; default is
`{"title","body","severity"}`)."""
import json
import re
import urllib.request

from nuncio.delivery import DeliveryAdapter, register

_DEFAULT_TEMPLATE = '{"title": "{title}", "body": "{body}", "severity": "{severity}"}'

# Only these literal tokens are substituted — NOT str.format(), which would
# require doubling every literal JSON brace in the template (unusable for
# operators). Everything else in the template passes through untouched.
_PLACEHOLDER = re.compile(r"\{(title|body|severity|headline|summary|host|service)\}")


def _urllib_transport(url, data_bytes, headers, timeout=10):
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def _escape(s):
    # JSON-escape the value without the surrounding quotes the template
    # already supplies.
    return json.dumps(s if s is not None else "")[1:-1]


def _render(template, title, body, severity, headline="", summary="", host="", service=""):
    values = {
        "title": _escape(title), "body": _escape(body), "severity": _escape(severity),
        "headline": _escape(headline), "summary": _escape(summary),
        "host": _escape(host), "service": _escape(service),
    }
    return _PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


@register
class Webhook(DeliveryAdapter):
    name = "webhook"

    def __init__(self, cfg=None, transport=None, timeout=10):
        cfg = cfg or {}
        self.url = cfg.get("url") or None
        self.headers = dict(cfg.get("headers") or {})
        self.headers.setdefault("Content-Type", "application/json")
        self.template = cfg.get("template") or _DEFAULT_TEMPLATE
        self._transport = transport or _urllib_transport
        self.timeout = timeout

    def send(self, title, body, severity="unknown", **kw):
        if not self.url:
            return False
        rendered = _render(
            self.template, title, body, severity,
            headline=kw.get("headline") or "", summary=kw.get("summary") or "",
            host=kw.get("host") or "", service=kw.get("service") or "",
        )
        try:
            json.loads(rendered)  # fail closed on a template producing invalid JSON
        except ValueError:
            return False
        status = self._transport(self.url, rendered.encode("utf-8"), self.headers, self.timeout)
        return 200 <= status < 300
