"""Generic best-effort webhook adapter — the fallback for any tool that
isn't a launch adapter.

Sniffs common field names out of whatever JSON was POSTed; if nothing
matches, the whole body is pretty-printed as `raw_text` so nothing is
silently dropped. This is `NUNCIO_DEFAULT_SOURCE`'s default value, i.e. what
`POST /ingest` (no explicit source) falls back to, and is also reachable
directly at `POST /ingest/generic`.

Deliberate, narrow exception to "parse() MUST be pure / no clock" (the base
SourceAdapter contract): the dedup key is `sha256(body) + received-minute`,
which needs an ingest-time clock because an arbitrary payload carries no
reliable native timestamp to derive one from instead. The clock is a module
attribute so tests can monkeypatch `nuncio.sources.generic._clock`.
"""
import hashlib
import json
import time

from nuncio.model import ParsedAlert, normalize_severity
from nuncio.sources import SourceAdapter, register

_HOST_KEYS = ("host", "hostname", "instance")
_SERVICE_KEYS = ("service", "check", "alertname", "title")
_MESSAGE_KEYS = ("message", "output", "body", "description")
_SEVERITY_KEYS = ("severity", "state", "status")

_clock = time.time  # overridable for tests


def _first(payload, keys, default=None):
    for k in keys:
        v = payload.get(k)
        if v:
            return v
    return default


@register
class Generic(SourceAdapter):
    name = "generic"

    def parse(self, payload, headers):
        if not isinstance(payload, dict):
            raise ValueError("generic payload must be a JSON object")
        host = _first(payload, _HOST_KEYS, "-")
        service = _first(payload, _SERVICE_KEYS)
        state = _first(payload, _SEVERITY_KEYS, "unknown")
        message = _first(payload, _MESSAGE_KEYS)
        if message is None:
            # Nothing recognizable matched: ship the whole body so it's never
            # silently dropped (the "any JSON" promise of this adapter).
            message = json.dumps(payload, sort_keys=True, indent=2, default=str)
        alert = {
            "host": host, "service": service, "state": str(state),
            "severity": normalize_severity(str(state)), "output": message,
            "source": self.name,
        }
        # host/service/output/timestamp are whatever type the arbitrary JSON
        # gave them (this adapter accepts ANY payload shape) -- coerce to str
        # so a nested dict/list never reaches the prompt f-strings untyped
        # (defense in depth; engine.py._enrich redacts non-strings too).
        self._coerce_str_fields(alert)
        canon = json.dumps(payload, sort_keys=True, default=str).encode()
        digest = hashlib.sha256(canon).hexdigest()[:16]
        minute_bucket = int(_clock() // 60)  # dedup tight retries, not distinct events
        key = f"{self.name}:{digest}/{minute_bucket}"
        raw = f"[{state}] {host}" + (f" / {service}" if service else "") + f" — {message}"
        return [ParsedAlert(key=key, alert=alert, raw_text=raw)]
