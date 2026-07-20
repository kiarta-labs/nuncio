"""Grafana unified-alerting webhook adapter.

Maps Grafana's contact-point webhook payload (`{"alerts":[...], ...}`) to
canonical ParsedAlert(s). One HTTP POST can carry multiple alerts (Grafana
batches firing/resolved alerts together), so `parse()` returns one per entry.

Point a Grafana webhook contact point at `POST /ingest/grafana` — no template
configuration needed, Grafana's default webhook body is used as-is.
"""
from nuncio.model import ParsedAlert, normalize_severity
from nuncio.sources import SourceAdapter, register


def _compact_values(values):
    """Deterministic, sorted-by-key rendering of Grafana's `values` map
    (refID -> number) used when `valueString` is absent/empty, e.g.
    {"A": 95.3, "B": 0} -> "A=95.3, B=0"."""
    return ", ".join(f"{k}={values[k]}" for k in sorted(values))


def _extract_value(a):
    """`alert["value"]` per-alert: prefer `valueString` (Grafana's own
    rendering of the evaluated expression, e.g. "[ var='A' ... value=95.3 ]");
    fall back to a compact rendering of `values` when `valueString` is
    absent/empty; omit entirely (return None) when neither is present."""
    value_string = a.get("valueString")
    if value_string:
        return str(value_string)
    values = a.get("values")
    if isinstance(values, dict) and values:
        return _compact_values(values)
    return None


def _extract_links(a):
    """`alert["links"]` per-alert: join the non-empty of runbook_url /
    panelURL / dashboardURL (in that order) with " · "; omit (return None)
    when none are present. generatorURL/silenceURL are deliberately excluded
    -- keep it to the operator-useful three."""
    annotations = a.get("annotations") or {}
    parts = [str(v) for v in (
        annotations.get("runbook_url"), a.get("panelURL"), a.get("dashboardURL"),
    ) if v]
    return " · ".join(parts) if parts else None


@register
class Grafana(SourceAdapter):
    name = "grafana"

    def parse(self, payload, headers):
        if not isinstance(payload, dict):
            raise ValueError("grafana payload must be a JSON object")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list) or not alerts:
            raise ValueError("grafana payload has no alerts[]")
        common_labels = payload.get("commonLabels") or {}
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
                host = labels.get("instance") or labels.get("host") or labels.get("hostname") or "-"
                service = labels.get("alertname") or common_labels.get("alertname")
                output = annotations.get("summary") or annotations.get("description") or ""
                # Lifecycle state is authoritative for a resolved alert -- the
                # rule's configured severity label is a *problem* severity and
                # must never be reported for a recovery (determinism doctrine).
                # A firing alert's real severity lives in the label; bare
                # "firing" is a lifecycle status, not a severity.
                if status == "resolved":
                    severity = "ok"
                else:
                    severity = normalize_severity(labels.get("severity") or "")
                fp = a.get("fingerprint", "0")
                starts = a.get("startsAt", "")
                alert = {
                    "host": host, "service": service, "state": status,
                    "severity": severity,
                    "output": output, "timestamp": starts, "source": self.name,
                }
                # labels/annotations come straight from arbitrary JSON -- coerce
                # defensively (see SourceAdapter._coerce_str_fields).
                self._coerce_str_fields(alert)
                value = _extract_value(a)
                if value:
                    alert["value"] = value
                links = _extract_links(a)
                if links:
                    alert["links"] = links
                key = f"{self.name}:{fp}/{status}/{starts}"
                raw = (f"[{status.upper()}] {host}"
                       + (f" / {service}" if service else "")
                       + f" — {output or '(no summary)'}")
                out.append(ParsedAlert(key=key, alert=alert, raw_text=raw))
            except Exception:
                out.append(self._fallback_parsed_alert(a, i))
        return out
