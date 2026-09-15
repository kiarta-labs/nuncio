"""Level-B context collectors.

Each collector is read-only, bounded (size/scope), and NEVER raises — on any
error it returns a `«context unavailable: <name>»` marker so a failed or slow
source degrades the bundle instead of blocking or crashing enrichment.

Data sources are injected callables (log-store query, docker inspect, CheckMK
query) so collectors are pure/testable; the deployed wiring supplies real
read-only clients.

Intelligence upgrades (still deterministic, decided by Nuncio itself, never LLM-driven):
- unit names are normalized via resolver.resolve_unit before querying;
- recent logs are relevance-RANKED against the alert's error tokens
  (relevance.rank_log_lines) instead of a blind tail;
- correlated alerts are scored + annotated with WHY they correlate
  (correlate.rank_correlated) when the alert is provided.
"""
from nuncio.correlate import rank_correlated
from nuncio.fingerprint import fingerprint
from nuncio.relevance import rank_log_lines
from nuncio.resolver import resolve_unit, extract_error_tokens

UNAVAIL = "«context unavailable: {}»"


def _cap_bytes(text, max_bytes):
    return text if len(text) <= max_bytes else text[-max_bytes:]


def collect_correlated(store, alert_key, now, window_s=600, limit=20,
                       alert=None, top_n=8, deps=None, host_domains=(), learned=None,
                       corrections=None):
    """Other alerts received in the backward window — this is what lets the LLM
    say 'the GPF storm and the postgres wedge are the same box'.

    When `alert` is provided, entries pass through the causal-entity GATE
    (fingerprint / unit-or-service equality / declared dependency edge —
    see nuncio.correlate's module docstring for the ratified model) and are
    annotated with WHY they correlate, best first; a same-host row that
    fails the gate may still appear, but only labeled "also active on
    <host>" — never a causal reason. Without `alert`, the legacy plain
    listing is kept. `deps` is an optional {service: [upstream, ...]} map
    and `host_domains` the configured DNS-suffix tuple (both see
    nuncio.correlate.rank_correlated)."""
    try:
        rows = store.recent(before=now, window_s=window_s, exclude_key=alert_key, limit=limit)
        mins = int(window_s // 60)
        if not rows:
            return f"## Correlated alerts\n(none in the last {mins} min)"
        if alert is not None:
            ranked = rank_correlated(rows, alert, tokens=extract_error_tokens(alert),
                                     now=now, window_s=window_s, top_n=top_n, deps=deps,
                                     host_domains=host_domains, learned=learned,
                                     corrections=corrections)
            if ranked:
                return (f"## Correlated alerts (last {mins} min, most related first)\n"
                        + "\n".join(ranked))
            # Post-Phase-3, an empty `ranked` means the causal-entity gate
            # excluded every row -- NOT an internal failure -- so this must
            # NOT fall through to the raw listing below (that would leak
            # every unrelated row's summary into the LLM's context, the #2
            # bleed). Mirrors collect_history's identical empty-ranked case.
            return f"## Correlated alerts\n(none related in the last {mins} min)"
        lines = [f"- {str(row[1]).splitlines()[0][:200]}" for row in rows]
        return f"## Correlated alerts (last {mins} min)\n" + "\n".join(lines)
    except Exception:
        return UNAVAIL.format("correlated")


def collect_recurrence(store, alert, now, window_s=172800):
    """How often this alert's fingerprint has recurred in the backward
    window — the LLM's signal for "this is a known/repeating problem" vs. a
    one-off. Annotation only (see nuncio.fingerprint's module docstring): this
    NEVER suppresses a delivery, it only adds context to it."""
    try:
        hours = max(1, int(window_s // 3600))
        fp = fingerprint(alert)
        if not fp:
            return "## Recurrence\n(no stable signature for this alert)"
        count, first_seen = store.fingerprint_stats(fp, window_s, now=now)
        if count <= 1:
            return f"## Recurrence\n(first occurrence in {hours}h)"
        age_s = max(0.0, float(now) - float(first_seen)) if first_seen is not None else 0.0
        ago = _format_ago(age_s)
        return (f"## Recurrence\n{_ordinal(count)} occurrence of this signature "
                f"in {hours}h; first seen {ago}")
    except Exception:
        return UNAVAIL.format("recurrence")


# Change-hint keywords matched (case-insensitive substring) against recent
# payload first-lines. Deliberately narrow stems, not a classifier: every
# hit is labeled as a keyword hit in the rendered section so the model (and
# the operator reading the bundle audit) can see exactly why it was
# included. No hit is ever treated as causal -- this section is context.
_CHANGE_KEYWORDS = ("updat", "upgrad", "deploy", "restart", "reboot",
                    "migrat", "firmware", "config change")


def collect_changes(store, alert, alert_key, now, window_s=3600, limit=100):
    """What changed around this alert in the backward window (C2): same-
    service recent events plus keyword change hints from other services'
    payloads. Store-only (no network I/O), like recurrence/history --
    "already-available signals" only, no new feed to configure. Never
    raises; empty (or store error via UNAVAIL) degrades like every other
    collector. Results are HINTS, never causal claims (no gate here)."""
    try:
        mins = max(1, int(window_s // 60))
        header = f"## Recent changes (last {mins}m)"
        rows = store.recent(before=now, window_s=window_s, exclude_key=alert_key, limit=limit)
        service = (alert.get("service") or "") if isinstance(alert, dict) else ""
        service_norm = service.strip().lower() or None
        same, hints, seen_hints = [], [], set()
        for row in rows or []:
            try:
                _key, payload, _created, _src, _cat, _sev, _fp, _host, r_service = row
            except (TypeError, ValueError):
                continue
            first = str(payload or "").splitlines()
            first = first[0][:160] if first and first[0].strip() else ""
            if not first:
                continue
            if service_norm and str(r_service or "").strip().lower() == service_norm:
                same.append(first)
                continue
            lowered = first.lower()
            if any(k in lowered for k in _CHANGE_KEYWORDS) and first not in seen_hints:
                seen_hints.add(first)
                hints.append(first)
        lines = []
        if same:
            lines.append(f"- {len(same)} same-service event(s); latest: {same[-1]}")
        for hit in hints[:5]:
            lines.append(f"- change hint: {hit}")
        if not lines:
            return f"{header}\n(no recent changes)"
        return header + "\n" + "\n".join(lines)
    except Exception:
        return UNAVAIL.format("changes")


def collect_past_incidents(store, alert, now, limit=3):
    """C5: previously-RESOLVED instances of this alert's fingerprint as a
    capped `## Similar past incidents` section -- the RAG source that lets
    the model cite what actually fixed this exact problem before, instead
    of re-deriving it. Store-only (free, like recurrence/history); reads
    ONLY the already-redacted enrichment/payload first lines (rule 1), so
    it is safe on both trust tiers. Never raises; empty/failure renders the
    honest empty marker."""
    try:
        fp = fingerprint(alert)
        if not fp:
            return "## Similar past incidents\n(no past occurrence)"
        rows = store.past_incidents(fp, limit=limit, now=float(now)) or []
        if not rows:
            return "## Similar past incidents\n(no past occurrence)"
        lines = []
        for created, _status, first, _pay in rows:
            try:
                age_s = max(0.0, float(now) - float(created))
                if age_s < 3600:
                    ago = f"{int(age_s // 60)}m ago"
                elif age_s < 86400:
                    ago = f"{int(age_s // 3600)}h ago"
                else:
                    ago = f"{int(age_s // 86400)}d ago"
            except (TypeError, ValueError):
                ago = ""
            lines.append(f"- {ago}: {first}" if ago else f"- {first}")
        return "## Similar past incidents\n" + "\n".join(lines)
    except Exception:
        return UNAVAIL.format("past_incidents")


def _ordinal(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if 10 <= (n % 100) <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _format_ago(age_s):
    if age_s < 3600:
        return f"{int(age_s // 60)}m ago"
    if age_s < 86400:
        return f"{int(age_s // 3600)}h ago"
    return f"{int(age_s // 86400)}d ago"


def collect_recent_logs(log_query, alert, window_s=900, max_lines=100, max_bytes=8000):
    """Recent log lines for the affected unit. `log_query(host, unit, window_s)`
    -> list[str], newest-last."""
    try:
        host = alert.get("host")
        unit = resolve_unit(alert) or alert.get("service")
        lines = log_query(host, unit, window_s) or []
        if not lines:
            return f"## Recent logs ({host}/{unit})\n(no matching log lines)"
        kept = rank_log_lines(lines, tokens=extract_error_tokens(alert),
                              service=alert.get("service"), host=host,
                              max_lines=max_lines, max_bytes=max_bytes)
        body = _cap_bytes("\n".join(kept), max_bytes)
        return f"## Recent logs ({host}/{unit}, last {int(window_s//60)}m)\n{body}"
    except Exception:
        return UNAVAIL.format("recent_logs")


def collect_container_state(docker_inspect, alert, max_log_lines=50):
    """Read-only container state + tail logs. `docker_inspect(name)` -> dict or None."""
    try:
        name = resolve_unit(alert) or alert.get("service") or alert.get("host")
        info = docker_inspect(name)
        if not info:
            return "## Container state\n(container not found)"
        head = (f"status={info.get('status')} restarts={info.get('restart_count')} "
                f"exit={info.get('exit_code')} started={info.get('started_at')}")
        logs = "\n".join((info.get("logs") or [])[-max_log_lines:])
        return f"## Container state ({name})\n{head}\n{logs}".rstrip()
    except Exception:
        return UNAVAIL.format("container_state")


def collect_metrics(checkmk_query, alert, limit=40):
    """Related metrics for the affected host/service. `checkmk_query(host, service)`
    -> list[str] summary lines."""
    try:
        rows = checkmk_query(alert.get("host"), alert.get("service")) or []
        if not rows:
            return "## Related metrics\n(none)"
        return "## Related metrics\n" + "\n".join(rows[:limit])
    except Exception:
        return UNAVAIL.format("metrics")


def collect_kernel(log_query, alert, window_s=900, max_lines=50):
    """Kernel/journal excerpt for hardware/kernel alerts; a flood (e.g. 100+/day
    GPFs) is SAMPLED (head+tail+count) not dumped. `log_query(host, facility, w)`."""
    try:
        host = alert.get("host")
        lines = log_query(host, "kern", window_s) or []
        if not lines:
            return f"## Kernel/journal ({host})\n(no matching lines)"
        if len(lines) > max_lines:
            h = max_lines // 2
            body = ("\n".join(lines[:h]) + f"\n... [{len(lines) - max_lines} more lines] ...\n"
                    + "\n".join(lines[-h:]))
        else:
            body = "\n".join(lines)
        return f"## Kernel/journal ({host}, last {int(window_s//60)}m)\n{body}"
    except Exception:
        return UNAVAIL.format("kernel")


def collect_history(store, alert_key, now, alert, window_s=86400, back_edge_s=600,
                     limit=120, top_n=15, deps=None, host_domains=(), learned=None,
                     corrections=None):
    """Recent-alert-history correlation (Phase B, full depth) -- a WIDER
    backward window than `collect_correlated`'s default, deliberately
    store-only (no network I/O) so even a bare install (all-null collector
    clients) gets real cross-alert history for free.

    The backward window is `[now - window_s, now - back_edge_s)` -- rows
    already covered by the normal `collect_correlated` window
    (`[now - back_edge_s, now)`, typically `NUNCIO_CORRELATION_WINDOW_S`) are
    excluded here so the two sections never duplicate the same rows; this
    section is strictly the OLDER tail of the 24h lookback.

    Same causal-entity gate as `collect_correlated` (see
    nuncio.correlate's module docstring): unrelated old rows on the same box
    collapse to "also active on <host>" grouping labels (or drop out
    entirely) rather than fabricating root/symptom chains. `deps` and
    `host_domains` are passed through to `rank_correlated` -- previously
    `deps` was never wired here (a pre-existing inconsistency with
    `collect_correlated`; fixed alongside this gate).

    Never raises -- any failure degrades to the "(no related alerts)" empty
    case, same fail-safe posture as every other collector."""
    header = "## Alert history (24h)"
    try:
        span = max(0.0, float(window_s) - float(back_edge_s))
        rows = store.recent(before=now - back_edge_s, window_s=span,
                             exclude_key=alert_key, limit=limit)
        if not rows:
            return f"{header}\n(no related alerts)"
        ranked = rank_correlated(rows, alert, tokens=extract_error_tokens(alert),
                                 now=now, window_s=window_s, top_n=top_n, deps=deps,
                                 host_domains=host_domains, learned=learned,
                                 corrections=corrections)
        if not ranked:
            return f"{header}\n(no related alerts)"
        return header + "\n" + "\n".join(ranked)
    except Exception:
        return UNAVAIL.format("history")
