"""OpenObserve alert-destination webhook adapter.

OpenObserve alert destinations POST a user-defined JSON template — there is
no single fixed schema. Recommended destination template (paste into the O2
alert destination's "Body" field) so this adapter's field names line up:

    {
      "alert_name": "{alert_name}",
      "stream": "{stream_name}",
      "org_name": "{org_name}",
      "start_time": "{start_time}",
      "end_time": "{end_time}",
      "severity": "{alert_severity}",
      "message": "{alert_desc}",
      "query": "{sql}",
      "condition": "{condition}",
      "rows": "{rows}"
    }

The last three (`query`/`condition`/`rows`) are OPTIONAL and populate the
canonical `check_command`/`value`/`details` extras (see nuncio/prompt.py's
`_alert_block`) so a routed O2 log alert carries the firing query, the
condition/threshold, and the matched log rows as evidence for the LLM. They
are the biggest single enrichment win for O2 alerts. The RHS placeholder
names above (`{sql}`, `{condition}`, `{rows}`) are NOT confirmed O2 v0.91-EE
template variables — verify the actual available variable names in the O2
alert-destination editor at setup time and adjust the Body accordingly. The
adapter degrades cleanly (these three extras are simply omitted) when the
template doesn't populate them, or populates them under a different key --
see the alias lists in `parse()` below.

An additional OPTIONAL `"unit": "{container_name}"` (or `container`/
`container_name`) field, when the destination template can supply it (e.g. a
docker/container-scoped source stream), maps to `alert["unit"]` -- Phase
4.1's source-native evidence: `resolve_unit`/`resolve_unit_strict` then use
the real container name instead of falling back to the alert's own name,
so log-lookup and the Phase 3 correlation gate both key off the actual unit.

Point the destination at `POST /ingest/openobserve`. Field names are read
defensively (several common aliases) so a slightly different template still
parses instead of hard-failing.

Deliberate, narrow exception to "parse() MUST be pure / no clock" (the base
SourceAdapter contract), mirroring nuncio/sources/generic.py: if the
operator's destination template omits `start_time`, the idempotency key
falls back to an ingest-time minute-bucket rather than a hardcoded constant.
Falling back to a constant would make every firing of the same alert+stream
map to ONE key forever -- since `store.persist` is INSERT OR IGNORE, every
firing after the first would be silently dropped (true loss). The minute
bucket still dedupes tight retries within the same minute while letting
distinct firings in different minutes through. The clock is a module
attribute so tests can monkeypatch `nuncio.sources.openobserve._clock`.
"""
import json
import time

from nuncio.model import ParsedAlert, normalize_severity
from nuncio.sources import SourceAdapter, register

_clock = time.time  # overridable for tests


def _first(payload, *keys, default=""):
    for k in keys:
        v = payload.get(k)
        if v:
            return v
    return default


def _stringify(value):
    """Render an alias value (rows/condition/query) as `str`, deterministically
    and without ever raising. Strings pass through unchanged; dict/list/other
    JSON-ish values use json.dumps(sort_keys=True) -- same rationale as
    SourceAdapter._coerce_str_fields (double-quoted keys keep the redactor's
    quote-delimited kv_secret/env rules working, unlike Python repr())."""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except Exception:  # pragma: no cover -- defensive, json.dumps essentially never raises with default=str
        return str(value)


def _render_rows(value):
    """`alert["details"]` from the optional `rows`/`result`/`records` alias:
    a string passes through as-is; a list renders one row per line (each row
    stringified via `_stringify` -- a dict row becomes one compact,
    deterministic (sort_keys) JSON line, a string row passes through, any
    other type falls back to `str()`); a single dict (not wrapped in a list)
    renders as one line the same way. Never raises."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(_stringify(row) for row in value)
    return _stringify(value)


@register
class OpenObserve(SourceAdapter):
    name = "openobserve"

    def parse(self, payload, headers):
        if not isinstance(payload, dict):
            raise ValueError("openobserve payload must be a JSON object")
        alert_name = _first(payload, "alert_name", "alertName", "alert", default="-")
        stream = _first(payload, "stream", "stream_name", "streamName", default="-")
        start_time = _first(payload, "start_time", "startTime", default="")
        severity = _first(payload, "severity", "alert_severity", default="warning")
        message = _first(payload, "message", "alert_desc", "description", default="")
        # Phase 3.6: stop defaulting host to org/stream -- every O2 alert on
        # the same org/stream would otherwise fabricate a shared "same host"
        # identity among ALL O2 alerts (the same class of bug as the "-"
        # wildcard, just a different literal). The stream still rides in
        # `raw_text`/`key`; a real per-alert host, when the destination
        # template supplies one, is picked up above.
        host = _first(payload, "host", "instance", default="-")
        alert = {
            "host": host, "service": alert_name, "state": "firing",
            "severity": normalize_severity(severity),
            "output": message, "timestamp": start_time, "source": self.name,
        }
        # O2's destination template is user-defined JSON -- coerce
        # defensively (see SourceAdapter._coerce_str_fields).
        self._coerce_str_fields(alert)
        # Phase 3: fold in the canonical "extra" keys (details/value/
        # check_command) from O2's richest optional template fields --
        # the matched log rows, the firing condition/threshold, and the
        # SQL/query -- rendered/capped by nuncio.prompt._alert_block, never
        # here. All three are OPTIONAL and set only when non-empty; must
        # not touch host/service/state/output/timestamp above or the `key`/
        # `raw_text` below (see module docstring).
        rows = _first(payload, "rows", "result", "records", default=None)
        if rows:
            alert["details"] = _render_rows(rows)
        condition = _first(payload, "condition", "threshold", "trigger", default=None)
        if condition:
            alert["value"] = _stringify(condition)
        query = _first(payload, "query", "sql", "vrl", default=None)
        if query:
            alert["check_command"] = _stringify(query)
        # Phase 4.1: optional unit/container template field -- the real
        # docker container / log-stream name, when the template supplies
        # one, so resolve_unit/resolve_unit_strict stop falling back to the
        # alert's own name. OPTIONAL and set only when non-empty; string-
        # coerced defensively like the other user-templated extras above.
        unit = _first(payload, "unit", "container", "container_name", default=None)
        if unit:
            alert["unit"] = _stringify(unit)
        # start_time absent (destination template omitted it): fall back to
        # an ingest-time minute-bucket, never a hardcoded constant -- see
        # module docstring for why a constant here means silent loss.
        bucket = start_time or str(int(_clock() // 60))
        key = f"{self.name}:{alert_name}/{stream}/{bucket}"
        raw = f"[{stream}] {alert_name} — {message or '(no message)'}"
        return [ParsedAlert(key=key, alert=alert, raw_text=raw)]
