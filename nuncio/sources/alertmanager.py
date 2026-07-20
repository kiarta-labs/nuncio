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
        for a in alerts:
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
            # labels/annotations come straight from arbitrary JSON -- coerce
            # defensively (see SourceAdapter._coerce_str_fields).
            self._coerce_str_fields(alert)
            key = f"{self.name}:{fp}/{status}/{starts}"
            raw = (f"[{status.upper()}] {host}"
                   + (f" / {service}" if service else "")
                   + f" — {output or '(no summary)'}")
            out.append(ParsedAlert(key=key, alert=alert, raw_text=raw))
        return out
