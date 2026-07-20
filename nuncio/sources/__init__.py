"""Source-adapter ring — the ingest side of Nuncio's narrow waist.

Adapters map ONE native monitoring-tool webhook payload to a list of
canonical `ParsedAlert`. Everything downstream (store, deadline, engine,
redactor, prompt, render, delivery) operates only on ParsedAlert — the core
never imports an adapter module directly; `nuncio/config.py` (the composition
root) is the only place adapters are looked up and wired to the HTTP server.

Adapters auto-register on import via the explicit list at the bottom of this
file (not pkgutil magic — transparent beats clever). A third party adds a
module + one import line here, or points `NUNCIO_EXTRA_SOURCES=mypkg.mymodule`
(comma-separated, imported at startup by config.py) without forking.
"""
import hashlib
import json

from nuncio.model import ParsedAlert

_REGISTRY = {}


def register(adapter_cls):
    """Class decorator: instantiate (no-arg constructor) and register an
    adapter by its `.name`. Re-registering the same name replaces the prior
    instance (useful for tests / hot-reloading a third-party override)."""
    _REGISTRY[adapter_cls.name] = adapter_cls()
    return adapter_cls


def get(name):
    return _REGISTRY.get(name)


def names():
    return sorted(_REGISTRY)


_CANONICAL_STR_FIELDS = ("host", "service", "output", "state", "timestamp")


class SourceAdapter:
    """The adapter interface."""
    name = None  # URL slug: POST /ingest/<name>

    @staticmethod
    def _coerce_str_fields(alert, fields=_CANONICAL_STR_FIELDS):
        """Defense in depth: coerce the canonical allowlisted alert fields to
        `str` (leaving `None` alone) at parse time, so no adapter can hand
        the engine a dict/list/int for a field the prompt builders
        (prompt.py) f-string unconditionally. This is a second layer
        alongside the engine's own handling (engine.py `_enrich` /
        `_redact_field`), which redacts every field's string representation
        regardless of type — that alone is sufficient, but adapters should
        not manufacture non-string canonical fields in the first place.

        Uses json.dumps (not str()) for non-string values, matching
        engine.py's `_redact_field`: Python's repr()/str() renders a dict
        with single quotes (`{'password': 'x'}`), which defeats the
        redactor's quote-delimited kv_secret/env rules, while json.dumps's
        double-quoted `"name": "value"` shape does not."""
        import json
        for f in fields:
            v = alert.get(f)
            if v is None or isinstance(v, str):
                continue
            try:
                alert[f] = json.dumps(v, sort_keys=True, default=str)
            except Exception:
                alert[f] = str(v)
        return alert

    def _fallback_parsed_alert(self, entry, index):
        """Best-effort ParsedAlert for a batch entry a source adapter could
        not shape into its normal canonical fields (e.g. Grafana/Alertmanager
        `alerts[]` containing a non-dict entry, or a dict with a list-valued
        `labels`). This is the never-lose backstop for per-entry fault
        isolation: a malformed entry must degrade to a raw alert, NEVER
        silently vanish and NEVER take down the well-formed siblings in the
        same batch (server.py's ingest() maps any parse()-time exception to a
        400 that would otherwise drop the whole POST).

        `index` is accepted for call-site symmetry with `enumerate(alerts)`
        but deliberately NOT used in the idempotency key -- the key is
        derived from a content hash so the SAME malformed entry always
        produces the SAME key across a source's retries (an index-based key
        would churn on retry if the batch's entry order or length changes,
        defeating idempotent dedup)."""
        try:
            rendering = json.dumps(entry, sort_keys=True, default=str)
        except Exception:
            rendering = repr(entry)
        rendering = rendering[:2000]
        digest = hashlib.sha256(rendering.encode("utf-8", "replace")).hexdigest()[:16]
        key = f"{self.name}:badentry/{digest}"
        alert = self._coerce_str_fields({
            "host": "-", "service": None, "state": "unknown", "severity": "unknown",
            "output": f"unparseable {self.name} batch entry: {rendering}",
            "timestamp": "", "source": self.name,
        })
        raw_text = f"[UNPARSEABLE] {self.name} batch entry — {rendering}"
        return ParsedAlert(key=key, alert=alert, raw_text=raw_text)

    def parse(self, payload: dict, headers: dict):
        """Map ONE native POST body to a list[ParsedAlert]. May return
        several (Prometheus Alertmanager and Grafana both batch multiple
        alerts in one webhook body). Raise ValueError on unparseable input
        (the server maps that to HTTP 400). MUST be pure: no I/O, no clock
        (use payload timestamps) — see nuncio/sources/generic.py for the one
        documented, narrow exception and why it's necessary."""
        raise NotImplementedError


# Explicit built-in registrations (import order doesn't matter; each module
# self-registers via the @register decorator on import).
from nuncio.sources import checkmk  # noqa: E402,F401
from nuncio.sources import grafana  # noqa: E402,F401
from nuncio.sources import alertmanager  # noqa: E402,F401
from nuncio.sources import openobserve  # noqa: E402,F401
from nuncio.sources import generic  # noqa: E402,F401
