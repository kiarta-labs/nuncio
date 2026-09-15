"""Prometheus Alertmanager webhook adapter.

Maps Alertmanager's `webhook_config` payload (`{"alerts":[...]}`) to
canonical ParsedAlert(s); one POST commonly batches several alerts (firing +
resolved together). Point an Alertmanager receiver at `POST
/ingest/alertmanager` with `send_resolved: true` so resolutions are visible
too.
"""
import hashlib
import json

from nuncio.model import ParsedAlert, normalize_severity
from nuncio.sources import SourceAdapter, register


def _labels_hash(labels):
    """Fallback idempotency source when `fingerprint` is absent (older
    Alertmanager / a hand-rolled webhook_config test payload) — a stable hash
    of the sorted label set."""
    canon = json.dumps(labels, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def _extract_value(entry):
    """The value behind the alert: `annotations.value` (Prometheus-style
    string), else `valueString`, else the compacted per-series values. Mirrors
    Grafana's `_extract_value` shape without importing it (alertmanager must
    stay a leaf module)."""
    try:
        annotations = entry.get("annotations") or {}
        v = annotations.get("value") or annotations.get("valueString")
        if v is not None:
            return str(v)
        values = entry.get("values")
        if isinstance(values, dict):
            return ",".join(f"{k}={val}" for k, val in sorted(values.items()))
    except Exception:
        return None
    return None


def _extract_links(annotations):
    """Runbook link(s) from annotations (Alertmanager conventions:
    `runbook_url` / `runbook` / `wiki`). Keep it to runbook-type links —
    generator/silence URLs are operational plumbing, not enrichment."""
    try:
        parts = []
        for key in ("runbook_url", "runbook", "wiki"):
            v = (annotations.get(key) or "").strip()
            if v:
                parts.append(str(v))
        return " · ".join(parts) or None
    except Exception:
        return None


@register
class Alertmanager(SourceAdapter):
    name = "alertmanager"

    def parse(self, payload, headers):
        if not isinstance(payload, dict):
            raise ValueError("alertmanager payload must be a JSON object")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not alerts:
            raise ValueError("alertmanager payload has no alerts[]")
        out = []
        for i, a in enumerate(alerts):
            # Per-entry fault isolation: one malformed entry (non-dict, or a
            # dict whose labels/annotations aren't dicts) must not abort the
            # whole batch -- it degrades to a best-effort raw ParsedAlert
            # instead, so the well-formed siblings in the same POST are never
            # lost. See SourceAdapter._fallback_parsed_alert.
            try:
                labels = a.get("labels") or {}
                annotations = a.get("annotations") or {}
                status = a.get("status", "unknown")
                host = labels.get("instance") or labels.get("host") or "-"
                service = labels.get("alertname")
                output = annotations.get("summary") or annotations.get("description") or ""
                fp = a.get("fingerprint") or _labels_hash(labels)
                starts = a.get("startsAt", "")
                # Lifecycle state is authoritative for a resolved alert -- the
                # rule's configured severity label is a *problem* severity and
                # must never be reported for a recovery (determinism doctrine).
                if status == "resolved":
                    severity = "ok"
                else:
                    severity = normalize_severity(labels.get("severity", status))
                alert = {
                    "host": host, "service": service, "state": status,
                    "severity": severity,
                    "output": output, "timestamp": starts, "source": self.name,
                }
                # C6 source parity with Grafana: surface the triggering value
                # (annotations value/valueString, else the summed values) and
                # the runbook link, so Alertmanager alerts carry the same
                # enrichment extras Grafana's already do.
                value = _extract_value(a)
                if value:
                    alert["value"] = value
                links = _extract_links(annotations)
                if links:
                    alert["links"] = links
                # labels/annotations come straight from arbitrary JSON -- coerce
                # defensively (see SourceAdapter._coerce_str_fields).
                self._coerce_str_fields(alert)
                key = f"{self.name}:{fp}/{status}/{starts}"
                raw = (f"[{status.upper()}] {host}"
                       + (f" / {service}" if service else "")
                       + f" — {output or '(no summary)'}")
                out.append(ParsedAlert(key=key, alert=alert, raw_text=raw))
            except Exception:
                out.append(self._fallback_parsed_alert(a, i))
        return out
