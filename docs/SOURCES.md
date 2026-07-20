# Writing a source adapter

A source adapter maps one native monitoring-tool webhook payload to a list of canonical alert dicts. Everything downstream of ingest — the store, redactor, prompt builder, engine, delivery — only ever sees the canonical shape, so the rest of Nuncio doesn't need to know anything about your tool.

Nuncio ships adapters for CheckMK, Grafana, Prometheus Alertmanager, and OpenObserve, plus a `generic` fallback for anything that doesn't have one.

## The interface

```python
from nuncio.sources import SourceAdapter, register

@register
class MySource(SourceAdapter):
    name = "mytool"  # becomes the URL slug: POST /ingest/mytool

    def parse(self, payload: dict, headers: dict) -> list[dict]:
        """Map ONE native POST body to a list of canonical alert dicts.
        May return more than one (Alertmanager and Grafana both batch
        multiple alerts in a single webhook call).

        Raise ValueError on unparseable input -- the server turns that
        into an HTTP 400.
        """
        return [{
            "host": payload["host"],
            "service": payload["check_name"],
            "state": payload["status"],       # e.g. "OK" / "WARNING" / "CRITICAL"
            "output": payload["message"],
            "timestamp": payload["time"],
        }]
```

## Canonical alert fields

| Field | Type | Meaning |
|---|---|---|
| `host` | str | The affected host/entity. |
| `service` | str | The check/service/rule name. |
| `state` | str | The tool's own state string (passed through, not normalized). |
| `output` | str | The human-readable alert text/body. |
| `timestamp` | str | The tool's own timestamp for the event. |

Non-string values in these fields are coerced to a JSON string representation at parse time — return strings directly where you can, but a stray int/dict won't break anything downstream.

## Severity and lifecycle state (determinism)

An adapter should also set a canonical `severity` — one of `ok`, `info`, `warning`, `critical`, `unknown`. This is the single value that drives the notification glyph AND the enrichment *disposition* (whether the alert is framed as a resolved recovery, a passive informational note, or an active problem), so it must be derived **deterministically from the source's own lifecycle state — never from a rule name, label, or free-text severity string the LLM might echo.**

The rule of thumb every built-in adapter follows:

- A **recovery / resolved** transition (`RECOVERY`, `status="resolved"`, an `OK`/`UP` state) → `severity="ok"`, **regardless of the firing rule's configured severity.** A rule labelled "critical" that just recovered is `ok`, not critical — otherwise a resolved alert would render with the problem glyph and a "likely cause" it no longer has. Grafana's and Alertmanager's adapters force `ok` on resolved for exactly this reason.
- A genuinely **informational** event with no problem/recovery semantics (a scheduled action report, a batch-complete notice) → `severity="info"`.
- Everything else maps the native state to `warning` / `critical`, or `unknown` when the payload is ambiguous.

Downstream, disposition is enforced in code, not left to the model: `ok` → recovery framing, `info` → a passive summary, and both have "likely cause" and "suggested checks" **stripped after inference** so a resolved or informational alert can never carry problem-framing even if the model tries to add it. Getting `severity` right in the adapter is therefore what makes the whole enrichment deterministic.

## Optional extra fields

Beyond the five base fields above, an adapter may also set any of the following canonical keys when the native payload has the data. They're rendered into the `## Alert` block alongside the base fields, each length-capped, and are entirely optional — omit any you don't have, they simply don't appear in the prompt.

| Field | Meaning |
|---|---|
| `details` | Long-form context — log excerpt, matched rows, extended plugin output. |
| `perfdata` | Raw performance/metric data attached to the check. |
| `check_command` | The check, query, or command that produced the alert. |
| `event` | The notification/event type (e.g. `PROBLEM`, `RECOVERY`). |
| `ack` | Acknowledgement author/comment, if the problem is acked. |
| `downtime` | Scheduled-downtime state, if any. |
| `groups` | Host/service group or tag membership. |
| `address` | The host's address/alias. |
| `recurrence` | A note that this is a repeat notification of the same problem. |
| `value` | The evaluated value/threshold that triggered the alert. |
| `links` | Related URLs — runbook, dashboard, panel. |

This is a fixed allowlist (see `nuncio/prompt.py`'s `_EXTRA_FIELD_SPECS`) — it's the boundary that keeps arbitrary adapter- or ingest-supplied keys from reaching the LLM as free-form prompt text. Setting a key outside this list on your alert dict has no effect; it's silently dropped when the prompt is assembled. Each field is length-capped and treated as data, not instructions, exactly like the base fields — see [`CONFIGURATION.md`](CONFIGURATION.md#extra-field-enrichment) for the caps and the built-in CheckMK/Grafana/OpenObserve adapters for worked examples of populating them from a native payload.

`parse()` must be pure: no I/O, no wall clock. Use timestamps from the payload itself. (The `generic` adapter is the one documented, narrow exception, because it has to cope with payloads that provide no timestamp at all — see `nuncio/sources/generic.py`.)

## Registering it

Adapters registered inside the `nuncio` package register themselves on import. A third-party adapter shipped as its own module registers the same way — just via `@register` in your own code — and gets loaded at startup by pointing `NUNCIO_EXTRA_SOURCES` at it:

```bash
NUNCIO_EXTRA_SOURCES=mypackage.mysource
```

Comma-separate multiple modules if you have more than one. No forking of Nuncio required.

## Testing your adapter

Feed it a real (or representative) payload captured from your tool and assert on the returned canonical dicts — see `tests/test_sources_*.py` for the pattern used by the built-in adapters.
