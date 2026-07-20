"""The web dashboard — a dependency-free, theme-aware transparency UI. One
Python module emitting a single self-contained HTML string (inline CSS +
inline vanilla JS, no fonts/frameworks/CDN/build step) plus the JSON
endpoints it polls.

Hard rule (never show a pre-redaction secret): every field this module
renders comes from `Store` columns that are ONLY ever written post-redaction --
  - `payload`  is `redact(raw_text)[0]`, written once at `server.App.ingest()`
  - `bundle`   is only ever written by `Engine._enrich()` from `redact(bundle)[0]`
  - `enrichment` is the LLM's own output over an already-redacted prompt
`/config.json` (unchanged, pre-existing) already dogfoods the redactor
itself. No code here re-reads a raw/unredacted alert field.

All statistical computation (rates, percentiles, windowing) happens HERE,
server-side, over plain Python lists pulled from SQLite — typical alert
volume (<10^3/day) makes that simpler and more portable than SQL window
functions (sqlite has no native percentile). The client-side JS stays
"dumb": it only polls the two JSON endpoints and plots the numbers it's
handed (including drawing the sparkline `<polyline>` points itself).
"""
import json
import re
from html import escape as _esc

from nuncio.web.shell import page_shell as _page_shell
from nuncio.web.shell import DETAIL_CSS as _DETAIL_CSS

_WINDOW_S = 24 * 3600
_SPARK_HOURS = 48

# outcome values that represent "a raw message shipped" for the purposes of
# the raw-rate / raw-fallback sparkline. "raw" is the only outcome the
# current engine writes; "raw_and_enriched"/"raw_only_final" are historical
# values from the retired raw_first delivery mode, kept here ONLY so old DB
# rows still bucket correctly on the sparkline.
_RAW_OUTCOMES = ("raw", "raw_and_enriched", "raw_only_final")


# --- pure aggregation helpers (independently testable, no I/O) ---

def percentile(values, p):
    """Nearest-rank-interpolated percentile over an already-sorted list of
    numbers. None for an empty input (there is nothing to report — the
    dashboard renders that as a null pill / em-dash, never a fabricated 0)."""
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    k = (len(values) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(values) - 1)
    if lo == hi:
        return values[lo]
    return values[lo] * (hi - k) + values[hi] * (k - lo)


def _rate(numerator, denominator):
    return round(numerator / denominator, 4) if denominator else 0.0


def _hourly_buckets(rows, now, hours=_SPARK_HOURS):
    """Bucket `rows` (dicts with created_at/outcome/latency_ms) into `hours`
    trailing 1-hour buckets ending at `now`. Returns the three parallel
    arrays the dashboard's `spark_48h` contract wants."""
    start = now - hours * 3600
    ingested = [0] * hours
    raw_fallback = [0] * hours
    latencies_by_bucket = [[] for _ in range(hours)]
    for r in rows:
        created = r.get("created_at")
        if created is None:
            continue
        idx = int((created - start) // 3600)
        idx = max(0, min(hours - 1, idx))
        ingested[idx] += 1
        if r.get("outcome") in _RAW_OUTCOMES:
            raw_fallback[idx] += 1
        if r.get("latency_ms") is not None:
            latencies_by_bucket[idx].append(r["latency_ms"])
    p95_ms = [percentile(sorted(b), 0.95) or 0 for b in latencies_by_bucket]
    return {"ingested": ingested, "raw_fallback": raw_fallback, "p95_ms": p95_ms}


def _top_signatures(rows, limit=5):
    """Top recurring fingerprints (count>=2) from `rows` (dicts with
    fingerprint/created_at/source/severity/payload), sorted by count desc
    then most-recently-seen desc. Falsy fingerprints (None/"") are skipped --
    not every row carries one. Independently testable, no I/O."""
    groups = {}
    for r in rows:
        fp = r.get("fingerprint")
        if not fp:
            continue
        g = groups.setdefault(fp, {"fingerprint": fp, "count": 0, "last_seen": None,
                                    "source": None, "severity": None, "summary": ""})
        g["count"] += 1
        created = r.get("created_at")
        if created is not None and (g["last_seen"] is None or created >= g["last_seen"]):
            g["last_seen"] = created
            g["source"] = r.get("source")
            g["severity"] = r.get("severity")
            payload = r.get("payload") or ""
            g["summary"] = payload.splitlines()[0][:120] if payload else ""
    top = [g for g in groups.values() if g["count"] >= 2]
    top.sort(key=lambda g: (g["count"], g["last_seen"] or 0), reverse=True)
    return top[:limit]


_TAG_RE = re.compile(r"^\[[^\]]*\]\s*")


def _norm_subject_field(value):
    """"-"/"" -> None. Non-CheckMK adapters (grafana/alertmanager/generic)
    default a missing host to the literal "-" and persist it -- untreated
    that keys the hosts ledger on a phantom "-" host. Whitespace-stripped
    too: old CheckMK rows and every non-CheckMK raw_text put spaces around
    the "/" (`svr / Filesystem`), so an un-stripped value from a payload
    parse ("svr ") would never match a clean column value ("svr") and split
    one real host into two ledger buckets."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if value and value != "-" else None


def _key_host_service(key):
    """Parse a CheckMK idempotency key
    (`checkmk:{host}/{service}/{pid}/{ntype}/{num}`) into (host, service).
    (None, None) for a non-CheckMK key, or a CheckMK key whose service
    itself contains a "/" (e.g. "Filesystem /var") -- splitting on "/" then
    yields 6+ parts, not the expected 5, and this deliberately does NOT
    attempt anything cleverer; the payload parse below handles that case
    fine via partition() (which only ever splits on the FIRST "/")."""
    if not key.startswith("checkmk:"):
        return None, None
    parts = key[len("checkmk:"):].split("/")
    if len(parts) != 5:
        return None, None
    return _norm_subject_field(parts[0]), _norm_subject_field(parts[1])


def _payload_host_service(payload):
    """Parse the first line of a (post-redaction) raw_text/payload string
    into (host, service). Every adapter's raw_text is either
    `[TAG] host / service — output`, `[TAG] host — output` (old CheckMK /
    all of grafana+alertmanager+generic), or `{emoji} host/service — output`
    (current CheckMK, no spaces). A line with no " — " separator at all
    carries no recognizable subject structure -- (None, None), not the whole
    line mistaken for a host."""
    if not payload:
        return None, None
    line = payload.splitlines()[0]
    line = _TAG_RE.sub("", line, count=1)
    if line and ord(line[0]) > 127:
        # a leading emoji/symbol severity token (e.g. "❗ ") -- real
        # ASCII hosts/tags never start above U+007F, so this can't
        # false-positive on a literal "-" host or a bracket tag.
        line = line[1:].lstrip()
    if " — " not in line:
        return None, None
    entity = line.split(" — ", 1)[0]
    host, sep, service = entity.partition("/")
    return _norm_subject_field(host), _norm_subject_field(service) if sep else None


def _derive_host_service(row):
    """Human-facing (host, service) for an alert row. Columns win outright
    when the host column is present (post-normalization) -- a CheckMK
    host-level notification legitimately has service=NULL, so this never
    tries to invent one by parsing. Only when the host column is absent/"-"
    does this fall to the CheckMK-key parse, then the payload-line parse,
    each of which can still recover a lone `service` (columns' own service
    value is preserved as the final fallback so it's never silently
    dropped just because host wasn't in a column). `row.get("key"/"payload")`
    are None-guarded -- the aggregation helpers below are called with dicts
    that don't always carry every field, and a raw AttributeError here would
    500 /stats.json (no try/except wraps build_stats)."""
    host_col = _norm_subject_field(row.get("host"))
    service_col = _norm_subject_field(row.get("service"))
    if host_col is not None:
        return host_col, service_col

    key_host, key_service = _key_host_service(row.get("key") or "")
    if key_host is not None:
        return key_host, key_service if key_service is not None else service_col

    payload_host, payload_service = _payload_host_service(row.get("payload") or "")
    if payload_host is not None:
        return payload_host, payload_service if payload_service is not None else service_col

    return None, service_col if service_col is not None else payload_service


def _subject(row):
    """Human-facing "subject" for an alert row: host/service when both are
    known, else whichever one is, else the payload's/key's own text, else an
    em dash (only truly impossible for a persisted row). Pure string
    formatting, no I/O."""
    host, service = _derive_host_service(row)
    if host and service:
        return f"{host}/{service}"
    if host:
        return host
    if service:
        return service
    payload = row.get("payload") or ""
    if payload:
        return payload.splitlines()[0][:80]
    return row.get("key") or "—"


def _hourly_counts(rows, now, hours=24):
    """Plain trailing hourly bucket COUNTS (oldest -> newest) ending at
    `now` -- the building block behind `by_host_24h`'s per-host sparkline.
    Unlike `_hourly_buckets` above this tracks nothing but the count (no
    outcome/latency split)."""
    start = now - hours * 3600
    buckets = [0] * hours
    for r in rows:
        created = r.get("created_at")
        if created is None:
            continue
        idx = int((created - start) // 3600)
        idx = max(0, min(hours - 1, idx))
        buckets[idx] += 1
    return buckets


def _median(values):
    vals = sorted(values)
    n = len(vals)
    if n == 0:
        return 0
    mid = n // 2
    if n % 2:
        return vals[mid]
    return (vals[mid - 1] + vals[mid]) / 2


def _storm_bucket_indices(totals, min_abs=5, mult=3):
    """Indices into `totals` (a list of per-bucket counts) that qualify as a
    "storm" column -- total >= max(min_abs, mult * median-of-nonzero-columns).
    A relative-to-peers threshold, so a lone busy column can never storm
    against itself (median of one value is that value); it takes either a
    hard floor breach or several peer columns to set a low-enough baseline.
    Empty/all-zero input returns []."""
    nonzero = [t for t in totals if t > 0]
    if not nonzero:
        return []
    threshold = max(min_abs, mult * _median(nonzero))
    return [i for i, t in enumerate(totals) if t >= threshold]


def _flap_cycles(states):
    """Count completed PROBLEM->RECOVERY->PROBLEM cycles in an ordered
    sequence of "P"/"R" state letters (oldest -> newest). Consecutive
    duplicate states are collapsed first (two PROBLEM alerts in a row with no
    recovery between them is one state, not two). A recovery seen before any
    problem doesn't start a cycle."""
    cycles = 0
    seen_problem = False
    seen_recovery_since_problem = False
    prev = None
    for st in states:
        if st == prev:
            continue
        prev = st
        if st == "P":
            if seen_recovery_since_problem:
                cycles += 1
                seen_recovery_since_problem = False
            seen_problem = True
        else:  # "R"
            if seen_problem:
                seen_recovery_since_problem = True
    return cycles


def _by_host_24h(rows_24h, rows_prior_24h, now, limit=6):
    """Up to `limit` hosts by 24h alert count, each with a trend vs. the
    PRIOR 24h window, an hourly sparkline, a severity mix, and enrich share.
    Rows without a `host` are skipped entirely (nothing to attribute them
    to). Pure, no I/O -- `rows_24h`/`rows_prior_24h` are already-fetched
    row dicts."""
    hosts = {}
    for r in rows_24h:
        h, _ = _derive_host_service(r)
        if not h:
            continue
        g = hosts.setdefault(h, {"host": h, "count": 0, "crit": 0, "warn": 0, "info": 0,
                                  "enriched_count": 0, "total_for_enrich": 0, "rows": []})
        g["count"] += 1
        g["rows"].append(r)
        sev = r.get("severity")
        if sev == "critical":
            g["crit"] += 1
        elif sev == "warning":
            g["warn"] += 1
        else:
            g["info"] += 1
        if r.get("outcome") == "enriched":
            g["enriched_count"] += 1
        g["total_for_enrich"] += 1

    prior_counts = {}
    for r in rows_prior_24h:
        h, _ = _derive_host_service(r)
        if not h:
            continue
        prior_counts[h] = prior_counts.get(h, 0) + 1

    out = []
    for h, g in hosts.items():
        prior = prior_counts.get(h, 0)
        count = g["count"]
        if prior == 0:
            trend = "new" if count > 0 else 0
        else:
            trend = round((count - prior) / prior * 100)
        out.append({
            "host": h, "count": count, "prior_count": prior, "trend_pct": trend,
            "spark": _hourly_counts(g["rows"], now, 24),
            "crit": g["crit"], "warn": g["warn"], "info": g["info"],
            "enriched_count": g["enriched_count"], "total_for_enrich": g["total_for_enrich"],
        })
    out.sort(key=lambda g: g["count"], reverse=True)
    return out[:limit]


def _noisiest_subjects_24h(rows_24h, limit=6):
    """Up to `limit` subjects (host/service) by 24h alert count, each with a
    has_critical flag, its max fingerprint-recurrence count, and a flap-cycle
    count/flag (see `_flap_cycles`). Rows are grouped by `_subject()`. Pure,
    no I/O."""
    subjects = {}
    for r in rows_24h:
        subj = _subject(r)
        g = subjects.setdefault(subj, {"subject": subj, "count": 0, "has_critical": False, "rows": []})
        g["count"] += 1
        g["rows"].append(r)
        if r.get("severity") == "critical":
            g["has_critical"] = True

    out = []
    for subj, g in subjects.items():
        rows = sorted(g["rows"], key=lambda r: r.get("created_at") or 0)
        fp_counts = {}
        for r in rows:
            fp = r.get("fingerprint")
            if fp:
                fp_counts[fp] = fp_counts.get(fp, 0) + 1
        recur = max(fp_counts.values()) if fp_counts else 0
        states = ["R" if r.get("severity") == "ok" else "P" for r in rows]
        flap_cycles = _flap_cycles(states)
        out.append({
            "subject": subj, "count": g["count"], "has_critical": g["has_critical"],
            "recur": recur, "flap_cycles": flap_cycles, "flapping": flap_cycles >= 2,
        })
    out.sort(key=lambda g: g["count"], reverse=True)
    return out[:limit] if limit else out


def _source_time_48h(rows_48h, now, hours=24, bucket_s=7200, top_n=5):
    """2h-bucketed (24 buckets over 48h) per-source grids for the
    source×time heatmap, plus the combined-across-sources storm columns.
    `rows_48h` is the already-fetched 48h row list. Pure, no I/O.

    Rendered as the full-width Source x Time heatmap in the Subjects section
    (see `sourceTime()` in the page JS)."""
    totals_by_source = {}
    for r in rows_48h:
        s = r.get("source")
        if not s:
            continue
        totals_by_source[s] = totals_by_source.get(s, 0) + 1
    sources = sorted(totals_by_source, key=lambda s: totals_by_source[s], reverse=True)[:top_n]

    start = now - hours * bucket_s
    grid = {s: [0] * hours for s in sources}
    raw_grid = {s: [0] * hours for s in sources}
    combined = [0] * hours
    for r in rows_48h:
        created = r.get("created_at")
        if created is None:
            continue
        idx = int((created - start) // bucket_s)
        idx = max(0, min(hours - 1, idx))
        combined[idx] += 1
        s = r.get("source")
        if s in grid:
            grid[s][idx] += 1
            if r.get("outcome") in _RAW_OUTCOMES:
                raw_grid[s][idx] += 1

    return {
        "sources": sources, "buckets": hours, "grid": grid, "raw_grid": raw_grid,
        "storm_cols": _storm_bucket_indices(combined),
    }


def _efficacy_24h(app, rows_24h, noisiest_subjects):
    """Fatigue/self-healing summary: how much noise was absorbed (dedup),
    how many problems self-recovered, and how many subjects are flapping.
    `noisiest_subjects` should be the FULL (uncapped) subject list, not the
    display-capped top 6, so `flapping_subjects` counts every flapper, not
    just the ones visible in the ledger."""
    problems = sum(1 for r in rows_24h if r.get("severity") and r.get("severity") != "ok")
    recovered_problems = sum(1 for r in rows_24h if r.get("severity") == "ok")
    flapping_subjects = sum(1 for g in noisiest_subjects if g.get("flapping"))
    return {
        "deduped": app.metrics.duplicates,
        "problems": problems,
        "recovered_problems": recovered_problems,
        "flapping_subjects": flapping_subjects,
    }


def _impl_label(impl):
    """Human-facing label for a collector's wired implementation. The
    "null" client sentinel (see nuncio/config.py `_client_impl_warning`) and a
    missing/empty impl both mean "not configured" -- the dashboard must never
    print the literal word "null" or a bare None, so both map to "off"."""
    if not impl or impl == "null":
        return "off"
    return impl


def _collectors_block(app):
    health = app.collector_health.snapshot() if app.collector_health else {}
    out = {}
    for name, impl in (app.collector_impls or {}).items():
        st = health.get(name, {})
        configured = bool(impl) and impl != "null"
        out[name] = {
            "impl": impl,
            "label": _impl_label(impl),
            "configured": configured,
            "ok": st.get("ok", True),
            "last_error": st.get("last_error"),
            "fail_24h": st.get("fail_count", 0),  # process-lifetime count, see CollectorHealth
        }
    return out


# --- /stats.json ---

def build_stats(app, now=None):
    """Everything /stats.json renders. `app` is
    the `nuncio.server.App` instance — this reads its store/metrics/config,
    never mutates anything (GET handlers must not mutate state, rule 2)."""
    now = app.wall_clock() if now is None else now

    status_counts = app.store.status_counts()
    totals = {
        "ingested": app.store.count_all(),
        "delivered_enriched": status_counts.get("delivered_enriched", 0),
        # "delivered_raw_and_enriched" is a historical status from the
        # retired raw_first delivery mode -- summed in here purely so old DB
        # rows still count correctly; nothing writes that status anymore.
        "delivered_raw": (status_counts.get("delivered_raw", 0)
                           + status_counts.get("delivered_raw_and_enriched", 0)),
        "duplicates": app.metrics.duplicates,
        "recovered": app.metrics.recovered,
        "shed": app.metrics.failures.get("queue", 0),
        "undelivered_now": status_counts.get("received", 0),
    }

    rows_48h = app.store.rows_since(now - _SPARK_HOURS * 3600)
    since_24h = now - _WINDOW_S
    rows_24h = [r for r in rows_48h if r["created_at"] >= since_24h]
    rows_prior_24h = [r for r in rows_48h if r["created_at"] < since_24h]

    latencies = sorted(r["latency_ms"] for r in rows_24h if r["latency_ms"] is not None)
    llm_latencies = sorted(r["llm_ms"] for r in rows_24h if r["llm_ms"] is not None)
    win_enriched = sum(1 for r in rows_24h if r["outcome"] == "enriched")
    win_raw = sum(1 for r in rows_24h if r["outcome"] in _RAW_OUTCOMES)

    fail_stages, by_source, by_category, by_severity = {}, {}, {}, {}
    for r in rows_24h:
        for bucket, key in ((fail_stages, "fail_stage"), (by_source, "source"),
                             (by_category, "category"), (by_severity, "severity")):
            v = r.get(key)
            if v:
                bucket[v] = bucket.get(v, 0) + 1

    window_24h = {
        "ingested": len(rows_24h),
        "enriched": win_enriched,
        "raw": win_raw,
        "enriched_rate": _rate(win_enriched, len(rows_24h)),
        "raw_rate": _rate(win_raw, len(rows_24h)),
        "p50_latency_ms": percentile(latencies, 0.50),
        "p95_latency_ms": percentile(latencies, 0.95),
        "max_latency_ms": latencies[-1] if latencies else None,
        "deadline_breaches": fail_stages.get("deadline", 0),
        "tokens_in": sum(r["tokens_in"] for r in rows_24h if r["tokens_in"]),
        "tokens_out": sum(r["tokens_out"] for r in rows_24h if r["tokens_out"]),
        "redactions": sum(r["redaction_count"] for r in rows_24h if r["redaction_count"]),
    }

    assist_attempted = sum(1 for r in rows_24h if r.get("assist_status"))
    assist_ok = sum(1 for r in rows_24h if r.get("assist_status") == "done")
    assist_failed = sum(1 for r in rows_24h if r.get("assist_status") == "failed")
    assist_24h = {"attempted": assist_attempted, "ok": assist_ok, "failed": assist_failed}

    private_cfg = (app.plane_info or {}).get("private", {})
    knowledge_cfg = (app.plane_info or {}).get("knowledge", {"enabled": False})
    assist_cfg = (app.plane_info or {}).get("assist", {"enabled": False})
    planes = {
        "private": {
            "model": private_cfg.get("model"),
            "calls_24h": sum(1 for r in rows_24h if r["llm_ms"] is not None),
            "errors_24h": sum(1 for r in rows_24h if r.get("fail_stage") in ("llm", "validate")),
            "p95_ms": percentile(llm_latencies, 0.95),
        },
        "knowledge": dict(knowledge_cfg),
        "assist": dict(assist_cfg),
    }

    spark_48h = _hourly_buckets(rows_48h, now)
    ns_full = _noisiest_subjects_24h(rows_24h, limit=None)

    return {
        "uptime_s": int(max(0.0, now - app.start_wall)),
        "version": app.version,
        "totals": totals,
        "window_24h": window_24h,
        "fail_stages_24h": fail_stages,
        "by_source_24h": by_source,
        "by_category_24h": by_category,
        "by_severity_24h": by_severity,
        "top_signatures_24h": _top_signatures(rows_24h),
        "assist_24h": assist_24h,
        "planes": planes,
        "queue": {"depth": app.metrics.queue_depth, "max": app.queue_max,
                  "concurrency": app.concurrency},
        "collectors": _collectors_block(app),
        "delivery": {"adapters": list(app.delivery_adapters or []),
                     "fail_24h": app.metrics.failures.get("delivery", 0)},
        "spark_48h": spark_48h,
        "spark_storm_48h": _storm_bucket_indices(spark_48h["ingested"]),
        "by_host_24h": _by_host_24h(rows_24h, rows_prior_24h, now),
        "noisiest_subjects_24h": ns_full[:6],
        "source_time_48h": _source_time_48h(rows_48h, now),
        "efficacy_24h": _efficacy_24h(app, rows_24h, ns_full),
    }


def render_stats_json(app):
    return json.dumps(build_stats(app), sort_keys=True).encode()


# --- /alerts.json ---

def render_alerts_json(app, limit=50, source=None, outcome=None):
    """Recent-alerts table data. Deliberately a lean
    projection — key/timing/outcome metadata + a one-line summary — NOT the
    full payload/bundle/enrichment text (that's the drill-down's job, rule 1
    "minimize exposure" even though the underlying text is already
    redacted)."""
    try:
        limit = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        limit = 50
    rows = app.store.recent_rows(limit=limit, source=source or None, outcome=outcome or None)
    alerts = []
    for r in rows:
        summary = ""
        if r.get("payload"):
            summary = r["payload"].splitlines()[0][:200]
        host, service = _derive_host_service(r)
        alert = {
            "key": r["key"], "created_at": r["created_at"], "source": r["source"],
            "category": r["category"], "severity": r["severity"], "outcome": r["outcome"],
            "fail_stage": r["fail_stage"], "latency_ms": r["latency_ms"],
            "tokens_in": r["tokens_in"], "tokens_out": r["tokens_out"], "summary": summary,
            "host": host, "service": service,
        }
        # subject is a client fallback ONLY for the truly-neither case -- a
        # host-None/service-present row (e.g. a grafana rule with no
        # instance label) must render the clean service name client-side,
        # not this raw-payload-derived string (see the client's 3-way branch
        # in render()).
        if host is None and service is None:
            alert["subject"] = _subject(r)
        alerts.append(alert)
    return json.dumps({"alerts": alerts}, sort_keys=True).encode()


# --- page shell (shared by / and /alert/<key> -- see nuncio/web/shell.py for
# the CSS + header/nav markup, reused verbatim by the settings screen) ---

# --- / (main dashboard) ---

_JS = r"""
const e = s => (s==null?'':String(s)).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const P = x => x==null ? '—' : (Math.round(x*1000)/10) + '%';
const M = x => x==null ? '—' : (x>=1000 ? (x/1000).toFixed(1)+'s' : Math.round(x)+'ms');
const N = x => x==null ? '—' : x.toLocaleString();
const T = t => t==null ? '—' : new Date(t*1000).toLocaleString();
const G = document.getElementById.bind(document);
const P2 = n => String(n).padStart(2,'0');
// tooltip time-range label -- buckets are ROLLING windows anchored to "now"
// (start = now - hours*3600 server-side), NOT clock-hour-aligned, so this
// labels actual minutes (e.g. "13:23-14:23"), never a dishonest "HH:00".
const HM = d => P2(d.getHours())+':'+P2(d.getMinutes());
const TR = (t0, t1) => HM(new Date(t0))+'–'+HM(new Date(t1));

function outcomeClass(o) {
  if (o && o.indexOf('raw') !== -1) return 'raw';
  if (o && o.indexOf('enriched') !== -1) return 'enriched';
  return 'null';
}

function pill(l, cls) { return '<span class="pill ' + cls + '">' + e(l) + '</span>'; }

function collectorPill(name, c) {
  const cls = !c.configured ? 'off' : (c.ok ? 'enriched' : 'fail');
  return pill(name + ': ' + c.label, cls);
}

function set(id, html) { const el = G(id); if (el) el.innerHTML = html; }

function chip(id, v, cls) {
  set('v-' + id, v);
  const el = G('chip-' + id);
  if (el) el.className = 'chip ' + cls;
}

// Every colored figure stays glued to its noun (class="nw" + a real
// non-breaking space) so a line break never stray a number from its word.
const nw = (n, word) => '<span class="nw"><strong>' + n + '</strong>&nbsp;' + word + '</span>';

function verdict(s) {
  const w = s.window_24h;
  if (!w.ingested) {
    return 'No signals in the last 24 hours. Nuncio is listening — check collector endpoints under Settings.';
  }
  const undelivered = s.totals.undelivered_now;
  if (undelivered > 0) {
    return '<span class="bad">' + nw(N(undelivered), 'alert' + (undelivered === 1 ? '' : 's') + ' undelivered') +
           '</span> right now.';
  }
  if (w.raw > 0) {
    return nw(N(w.ingested), 'alerts') + ' in the last 24 hours. ' +
           nw(N(w.enriched), 'enriched') + ', ' + nw(N(w.raw), 'raw') + ' shipped by the safety net.';
  }
  return nw(N(w.ingested), 'alerts') + ' in the last 24 hours, all enriched.';
}

function healthWord(s) {
  const w = s.window_24h;
  if (!w.ingested) return '';
  const errs = (s.planes.private && s.planes.private.errors_24h) || 0;
  return w.enriched_rate >= 0.9 && errs === 0 ? 'healthy' : w.enriched_rate >= 0.6 ? 'degraded' : 'raw-heavy';
}

// No p95 polyline here on purpose -- an unlabeled trend squiggle added noise
// without a legend; p95 already has its own labeled card + delta below.
function stripChart(s) {
  const ing = (s.spark_48h.ingested || []).map(x => x||0);
  const raw = (s.spark_48h.raw_fallback || []).map(x => x||0);
  const p95 = s.spark_48h.p95_ms || [];
  const n = ing.length || 48;
  const em = G('stripchart-empty');
  if (!ing.some(x=>x) && !raw.some(x=>x)) {
    if (em) em.style.display = 'block';
    set('stripchart', '');
    return;
  }
  if (em) em.style.display = 'none';
  const mx = Math.max.apply(null, ing.concat([1]));
  const bw = 480 / n, bwid = Math.max(0, bw-1).toFixed(1);
  const dt = document.documentElement.getAttribute('data-theme');
  const io = (dt ? dt === 'light' : matchMedia('(prefers-color-scheme:light)').matches) ? '.6' : '.45';
  const rect = (x, y, h, f, o) => '<rect x="' + x.toFixed(1) + '" y="' + y.toFixed(1) + '" width="' + bwid +
    '" height="' + h.toFixed(1) + '" fill="' + f + '"' + (o ? ' opacity="' + o + '"' : '') + '/>';
  const nowMs = Date.now(), startMs = nowMs - n*3600000;
  let bars = '';
  for (let i = 0; i < n; i++) {
    const bx = i*bw+0.5, h = (ing[i] / mx) * 60, t0 = startMs+i*3600000;
    const ttl = TR(t0, t0+3600000) + ' · ' + ing[i] + ' alert' + (ing[i]===1?'':'s') +
      (raw[i] ? ' (' + raw[i] + ' raw)' : '') + (p95[i] ? ' · p95 ' + M(p95[i]) : '');
    bars += '<g><title>' + e(ttl) + '</title><rect x="' + bx.toFixed(1) +
      '" y="0" width="' + bwid + '" height="60" fill="transparent"/>';
    bars += rect(bx, 60-h, h, 'var(--trace)', io);
    if (raw[i]) {
      const rh = (raw[i] / mx) * 60;
      bars += rect(bx, 60-rh, rh, '#E0A83E');
    }
    bars += '</g>';
  }
  const mid = (n/2*bw).toFixed(1);
  bars += '<line x1="' + mid + '" y1="0" x2="' + mid + '" y2="60" stroke="var(--border)" stroke-width="1"/>';
  (s.spark_storm_48h || []).forEach(i => {
    bars += '<rect class="stormcap" x="' + (i*bw+0.5).toFixed(1) + '" y="-4" width="' + bwid + '" height="2"/>';
  });
  set('stripchart', bars);
}

function delta(arr, invert) {
  arr = (arr || []).map(x => x||0);
  const f = arr.slice(0, 24).reduce((a,b) => a+b, 0), s2 = arr.slice(24, 48).reduce((a,b) => a+b, 0);
  if (!f && !s2) return '';
  if (!f) return '<span class="delta">new</span>';
  const pct = Math.round(((s2-f) / f) * 1000) / 10;
  if (pct === 0) return '<span class="delta">&middot; flat</span>';
  const up = pct > 0, improving = invert ? !up : up;
  return '<span class="delta ' + (up?'up':'down') + '-' + (improving?'good':'bad') + '">' +
         (up?'&#9650;':'&#9660;') + ' ' + Math.abs(pct) + '%</span>';
}

// Signal-path diagram: continuous verdigris spine, a node under each stage
// label, an amber fallback rail that physically diverges at stage #3 and
// rejoins before stage #4, and a dead-end shed stub off stage #1. Geometry
// is computed off the live stage-label layout (not a fixed viewBox) so
// nodes always land exactly under their labels, at any width.
function layoutSigPath() {
  const wrap = G('sigpath'), svg = G('sigpath-svg');
  if (!wrap || !svg) return;
  const st = wrap.querySelectorAll('.stagerow .stage');
  if (st.length !== 4) return;
  const wr = wrap.getBoundingClientRect(), w = Math.max(1, Math.round(wr.width));
  const sy = 26, dy = 46, shy = 40, r = 8, nr = 3.5;
  const xs = [].map.call(st, e => Math.round(e.getBoundingClientRect().left - wr.left + 14));
  const mx = Math.max(xs[2]+12, xs[3]-14), fx = xs[2], sx = xs[0];
  let s = '<line class="spine" x1="'+xs[0]+'" y1="'+sy+'" x2="'+xs[3]+'" y2="'+sy+'"/>';
  xs.forEach((x,i) => {
    s += '<line class="conn" x1="'+x+'" y1="0" x2="'+x+'" y2="'+sy+'"/>';
    s += '<circle class="'+(i===2?'junction':'node')+'" cx="'+x+'" cy="'+sy+'" r="'+nr+'"/>';
  });
  s += '<path class="rail" d="M '+fx+' '+sy+' L '+fx+' '+(dy-r)+' Q '+fx+' '+dy+' '+(fx+r)+' '+dy+' L '+(mx-r)+' '+dy+
       ' Q '+mx+' '+dy+' '+mx+' '+(dy-r)+' L '+mx+' '+sy+'"/>';
  s += '<circle class="merge" cx="'+mx+'" cy="'+sy+'" r="2.5"/>';
  s += '<path class="stub" d="M '+sx+' '+sy+' L '+sx+' '+shy+' M '+(sx-3)+' '+shy+' L '+(sx+3)+' '+shy+'"/>';
  svg.setAttribute('viewBox', '0 0 '+w+' 58');
  svg.setAttribute('width', w);
  svg.setAttribute('height', 58);
  svg.innerHTML = s;
  // Tag labels are positioned absolute against #sigpath, not the svg -- the
  // svg sits *after* the stage labels in normal flow, so its own y=0 isn't
  // #sigpath's y=0. Measure the real offset instead of assuming they match
  // (that mismatch previously let "shed N" land on top of "ingest N").
  const ot = Math.round(svg.getBoundingClientRect().top - wr.top);
  const ra = G('sp-raw'), sh = G('sp-shed');
  if (ra) { ra.style.left = Math.round((fx+mx)/2)+'px'; ra.style.top = (ot+dy+6)+'px'; }
  if (sh) { sh.style.left = sx+'px'; sh.style.top = (ot+shy+6)+'px'; }
}
window.onresize = layoutSigPath;

function sevClass(k) {
  if (k === 'critical') return 'sev-critical';
  if (k === 'warning') return 'sev-warning';
  return 'sev-info';
}

function renderBars(id, obj, rowClassFn) {
  const keys = Object.keys(obj || {}).sort((a,b) => obj[b]-obj[a]);
  if (!keys.length) { set(id, '<div class="empty">no data yet</div>'); return; }
  const max = Math.max.apply(null, keys.map(k => obj[k]).concat([1]));
  set(id, keys.map(k =>
    '<div class="barrow ' + (rowClassFn ? rowClassFn(k) : '') + '"><span class="barlabel">' + e(k) +
    '</span><span class="barcount">' + N(obj[k]) + '</span><div class="bar" style="width:' +
    Math.max(2, Math.round((obj[k]/max) * 100)) + '%"></div></div>'
  ).join(''));
}

function renderSignatures(list) {
  if (!list || !list.length) { set('signatures', '<div class="empty">no recurring signatures in 24h</div>'); return; }
  set('signatures', list.map(g =>
    '<div class="sigrow"><span class="sigcount">&times;' + g.count + '</span><span class="sigsummary">' +
    e(g.summary || g.fingerprint) + '</span><span class="sigmeta">' + e(g.source || '—') + ' &middot; ' +
    e(g.severity || '—') + ' &middot; ' + e(T(g.last_seen)) + '</span></div>'
  ).join(''));
}

// readout tape -- the topbar's status light
function tape(s) {
  const w=s.window_24h, u=s.totals.undelivered_now, d=new Date();
  set('tape', 'UNDELIVERED <b class="'+(u>0?'bad':'')+'">'+N(u)+'</b> &middot; Q '+
    s.queue.depth+'/'+s.queue.max+' &middot; ENR <b class="'+
    (w.enriched_rate<0.8?'warn':'')+'">'+P(w.enriched_rate)+
    '</b> &middot; LAST '+P2(d.getHours())+':'+P2(d.getMinutes())+':'+P2(d.getSeconds()));
}

// host ledger -- one hairline row per host, shared spark scale across rows.
// (severity mix is text-only, not a bar -- kept to budget; the sparkline and
// trend delta, which ARE the point of the row, are not touched.)
function hostLedger(list) {
  if (!list || !list.length) {
    set('hled', '<div class="empty">No subject data in this window yet — hosts appear as alerts arrive.</div>');
    return;
  }
  const gmax = Math.max.apply(null, list.map(g=>Math.max.apply(null,g.spark)).concat([1]));
  set('hled', list.map(g => {
    const tr=g.trend_pct;
    let tc='flat', tt='&mdash;';
    if (tr==='new') { tc='new'; tt='new'; }
    else if (tr>10) { tc='up'; tt='&#9650;'+Math.min(999,tr)+'%'; }
    else if (tr<-10) { tc='down'; tt='&#9660;'+Math.abs(tr)+'%'; }
    const pts = g.spark.map((v,i)=>(i*5+1)+','+(16-(v/gmax)*15).toFixed(1)).join(' ');
    const enr = g.total_for_enrich ? Math.round(g.enriched_count/g.total_for_enrich*100) : 0;
    const hshort = g.host.replace(/\.kirits\.net$/, '');
    const peak = Math.max.apply(null, g.spark);
    const sttl = e(g.host) + ' — hourly alerts, last 24h · total ' + g.count + ' · peak ' + peak + '/h';
    const mix = '<span style="color:var(--breach)">'+g.crit+'c</span>&middot;<span style="color:var(--raw)">'+
      g.warn+'w</span>&middot;<span style="color:var(--ink2)">'+g.info+'i</span>';
    return '<div class="hr"><span class="hh" title="'+e(g.host)+'">'+e(hshort)+'</span><span class="hn">'+N(g.count)+
      '</span><span class="htr '+tc+'">'+tt+'</span><svg width="120" height="16"><title>'+sttl+
      '</title><polyline points="'+pts+
      '" fill="none" stroke="var(--trace)" stroke-width="1.5"/></svg><span class="hmx">'+mix+
      '</span><span class="hen'+(enr<50?' low':'')+'">'+enr+'% enr</span></div>';
  }).join(''));
}

// ns subjects -- reuses the patterns barlist component verbatim
function ns(list) {
  if (!list || !list.length) { set('ns', '<div class="empty">no data yet</div>'); return; }
  const mx = Math.max.apply(null, list.map(g=>g.count).concat([1]));
  set('ns', list.map(g => {
    let b = '';
    if (g.flapping) b = '<span class="nsb" title="flapping — '+g.flap_cycles+
      ' problem/recovery cycles in 24h. Candidate for suppression.">&#8767;'+g.flap_cycles+'</span> ';
    else if (g.recur>=2) b = '<span class="nsb">&times;'+g.recur+'</span> ';
    const c = g.flapping ? 'var(--raw)' : g.has_critical ? 'var(--breach)' : 'var(--trace)';
    return '<div class="barrow"><span class="barlabel">'+b+e(g.subject)+'</span><span class="barcount">'+
      N(g.count)+'</span><div class="bar" style="width:'+Math.max(2,Math.round(g.count/mx*100))+
      '%;background:'+c+'"></div></div>';
  }).join(''));
}

// source x time heatmap -- 2h buckets over 48h, amber tint when a bucket's
// raw share is >=50%, red storm caps above columns that spike across ALL
// sources combined (same combined-storm concept as the 48h strip's caps,
// just localized to this grid's own bucketing).
function sourceTime(st) {
  let h = '<div class="sl">Source &times; time (48h)</div>';
  if (!st.sources.length) { set('sg', h+'<div class="empty">no data yet</div>'); return; }
  const vbw = st.buckets*12, op = [0,.06,.25,.5,.75,1], mid = st.buckets/2*12;
  const bucketMs = 7200000, startMs = Date.now() - st.buckets*bucketMs;
  st.sources.forEach(src => {
    const g=st.grid[src], rg=st.raw_grid[src];
    let c = '<svg viewBox="0 0 '+vbw+' 10" preserveAspectRatio="none" overflow="visible">';
    c += '<line x1="'+mid+'" y1="0" x2="'+mid+'" y2="10" stroke="var(--edge)" stroke-width="1" vector-effect="non-scaling-stroke"/>';
    st.storm_cols.forEach(i => { c += '<rect class="stormcap" x="'+(i*12)+'" y="-4" width="10" height="2"/>'; });
    for (let i=0; i<st.buckets; i++) {
      const n=g[i]||0, r=rg[i]||0, o=n?(op[Math.min(4,n)]||1):.06, t0=startMs+i*bucketMs;
      const ttl = e(src)+' · '+TR(t0, t0+bucketMs)+': '+n+(n&&r*2>=n?' ('+r+' raw)':'');
      c += '<rect x="'+(i*12)+'" width="10" height="10" fill="'+(n&&r*2>=n?'var(--raw)':'var(--trace)')+
        '" opacity="'+o+'"><title>'+ttl+'</title></rect>';
    }
    h += '<div class="row"><span class="sr">'+e(src)+'</span><div class="chart">'+c+'</svg></div></div>';
  });
  h += '<div class="axisrow"><span class="sr"></span><div class="axis">'+
    '<span>-48h</span><span>-24h</span><span>now</span></div></div>';
  set('sg', h);
}

function render(s, alerts) {
  const w = s.window_24h, t = s.totals;
  document.title = 'Nuncio — ' + N(t.ingested) + ' ingested';

  set('verdict', verdict(s));

  set('sp-ingested', N(w.ingested));
  set('sp-context', N(w.redactions) + ' redactions');
  set('sp-shed', 'shed ' + N(s.fail_stages_24h.queue || 0));
  set('sp-enriched', N(w.enriched));
  set('sp-raw', 'raw fallback ' + N(w.raw));
  set('sp-delivered', N(w.enriched + w.raw));
  layoutSigPath();

  const undelivered = t.undelivered_now;
  chip('undelivered', N(undelivered), undelivered > 0 ? 'bad' : 'ok');

  const er = w.enriched_rate;
  const hw = healthWord(s);
  chip('enriched-rate', P(er) + (hw ? ' <span class="muted">' + hw + '</span>' : ''), er < 0.8 ? 'warn' : 'ok');

  const breaches = w.deadline_breaches;
  chip('breaches', N(breaches), breaches > 0 ? 'bad' : 'ok');

  set('v-queue', s.queue.depth + ' / ' + s.queue.max);
  const queueChip = G('chip-queue');
  if (queueChip) queueChip.className = 'chip ' + (s.queue.depth >= s.queue.max ? 'warn' : 'ok');

  stripChart(s);

  set('v-ingested-24h', N(w.ingested));
  set('delta-ingested', delta(s.spark_48h.ingested));

  set('v-p95-latency', M(w.p95_latency_ms));
  set('sub-p95-latency', 'p50 ' + M(w.p50_latency_ms) + ' · max ' + M(w.max_latency_ms));
  set('delta-p95', delta(s.spark_48h.p95_ms, true));

  set('v-tokens', N(w.tokens_in + w.tokens_out));
  set('sub-tokens', 'in ' + N(w.tokens_in) + ' · out ' + N(w.tokens_out));

  const redactions = w.redactions;
  set('v-redactions', N(redactions));
  G('cardrx').className = 'c3' + (redactions === 0 ? ' twn' : '');

  const assist = s.assist_24h || {attempted: 0, ok: 0, failed: 0};
  const assistPlaneOn = !!(s.planes.assist && s.planes.assist.enabled);
  const assistTxt = (assist.attempted === 0 && !assistPlaneOn) ? 'off' : (N(assist.ok) + ' / ' + N(assist.attempted));
  set('vccnt', 'recovered <b>' + N(t.recovered) + '</b> since start &middot; dup/shed <b>' +
      N(t.duplicates) + '/' + N(t.shed) + '</b> &middot; assist <b>' + e(assistTxt) + '</b> external plane');

  const stripBits = [];
  const pv = s.planes.private;
  stripBits.push(pill('private: ' + (pv.model || 'unset'), pv.model ? 'enriched' : 'off'));
  stripBits.push(pill('knowledge: ' + (s.planes.knowledge.enabled ? (s.planes.knowledge.model || 'on') : 'off'),
                       s.planes.knowledge.enabled ? 'enriched' : 'off'));
  (s.delivery.adapters.length ? s.delivery.adapters : ['none']).forEach(a =>
    stripBits.push(pill('deliver: ' + a, a === 'none' ? 'off' : 'enriched')));
  Object.keys(s.collectors).forEach(name => stripBits.push(collectorPill(name, s.collectors[name])));
  set('health-strip', stripBits.join(''));

  renderBars('bars-source', s.by_source_24h);
  renderBars('bars-category', s.by_category_24h);
  renderBars('bars-severity', s.by_severity_24h, sevClass);
  renderBars('bars-failstage', s.fail_stages_24h, () => 'fail');
  renderSignatures(s.top_signatures_24h);

  tape(s);
  hostLedger(s.by_host_24h);
  ns(s.noisiest_subjects_24h);
  sourceTime(s.source_time_48h);
  const eff = s.efficacy_24h || {};
  const flapBit = eff.flapping_subjects ? ' &middot; <span class="amber">flapping ' + eff.flapping_subjects +
    ' subject' + (eff.flapping_subjects===1?'':'s') + '</span>' : '';
  set('hcnt', 'deduped <b>' + N(eff.deduped) + '</b> fatigue avoided' + flapBit);

  const SEV = {critical:['CRIT','crit','sev-crit'], warning:['WARN','warn','sev-warn']};
  let lastDay = '', rows = '';
  alerts.forEach(a => {
    const d = a.created_at ? new Date(a.created_at*1000) : null;
    const day = d ? d.toLocaleDateString(undefined,{day:'2-digit',month:'short'}).toUpperCase() : '';
    if (day && day !== lastDay) {
      rows += '<tr class="dv"><td colspan="8">'+day+'<span class="dvr"></span></td></tr>';
      lastDay = day;
    }
    const time = d ? [d.getHours(),d.getMinutes(),d.getSeconds()].map(x=>String(x).padStart(2,'0')).join(':') : '—';
    const sv = SEV[a.severity] || ['INFO','info',''];
    // three-way: host (+service if present) wins; else a lone service; else
    // the server's own subject fallback (only sent when BOTH are null) --
    // a host-less/service-present row must render the clean service name,
    // not an uglier raw-payload-line regression.
    const h = a.host, s2 = a.service;
    const subj = h ? ('<b>'+e(h)+'</b>'+(s2?' / '+e(s2):'')) : (s2 ? e(s2) : '<b>'+e(a.subject||'—')+'</b>');
    const outc = a.outcome && a.outcome.indexOf('raw') !== -1 ? '<span class="rwc">RAW</span>' :
      a.outcome && a.outcome.indexOf('enriched') !== -1 ? '<span class="enr">enriched</span>' : '&mdash;';
    const href = '/alert/' + encodeURIComponent(a.key);
    rows += '<tr class="arow '+sv[2]+'" data-href="'+href+'" tabindex="0" role="link"><td>'+e(time)+
      '</td><td class="cs">'+e(a.source||'—')+'</td><td class="sj">'+subj+'</td><td class="sev '+sv[1]+'">'+
      sv[0]+'</td><td class="c2">'+e(a.category||'—')+'</td><td class="oc">'+outc+'</td><td class="num lat'+
      (a.latency_ms>=10000?' slow':'')+'">'+M(a.latency_ms)+'</td><td class="num c2">'+
      (a.tokens_in!=null||a.tokens_out!=null?N((a.tokens_in||0)+(a.tokens_out||0)):'—')+'</td></tr>';
  });
  set('alerts-tbody', rows || '<tr><td colspan="8" class="muted">no alerts yet</td></tr>');
}

// one shared row-activation handler for the whole recent-alerts table
document.addEventListener('click', ev => {
  const row = ev.target.closest('tr.arow');
  if (!row || ev.target.closest('a')) return;
  location = row.dataset.href;
});
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const row = ev.target.closest && ev.target.closest('tr.arow');
  if (!row) return;
  ev.preventDefault();
  location = row.dataset.href;
});

async function refresh() {
  try {
    const [stats, alertsResp] = await Promise.all([
      fetch('stats.json').then(r => r.json()),
      fetch('alerts.json?limit=25').then(r => r.json()),
    ]);
    render(stats, alertsResp.alerts);
  } catch (e) {
    // transient fetch failure -- keep the last good render on screen
  }
}
refresh();
setInterval(refresh, 10000);
"""


def _minify_js(js):
    """Strip comment-only lines and leading/trailing indentation, dropping
    blank lines. Adjacent lines are then joined directly (no newline) when
    that's provably safe -- i.e. the earlier line already ends on a
    self-terminating token (`;{}(),:`) AND the next line doesn't open with a
    token that could fuse onto it into a different expression (`( [ \\` + -`
    -- the classic ASI hazards, e.g. a bare expression followed by a line
    starting with `(` silently becoming a function call on the previous
    line). Whenever that's not provably true, the newline is kept, so
    automatic-semicolon-insertion behavior is never at risk -- this is a
    conservative allowlist, not a full tokenizer, and it only ever REMOVES
    characters that don't change what the browser executes. Source stays
    fully commented/indented above; this only shrinks what actually ships."""
    lines = []
    for line in js.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        lines.append(stripped)
    if not lines:
        return ""
    out = lines[0]
    for prev, nxt in zip(lines, lines[1:]):
        safe = prev[-1:] in ";{}(),:" and nxt[:1] not in "([`+-"
        out += ("" if safe else "\n") + nxt
    return out


_JS = _minify_js(_JS)


def _minify_body(html):
    """Strip leading/trailing whitespace off each line of the static page
    skeleton and drop blank lines, same spirit as `_minify_js`/`_minify_css`.
    Unlike JS this has no ASI hazard -- HTML tag/attribute whitespace is
    insignificant, and no line here ends mid-attribute or mid-text -- so
    lines are joined with a single space (never '', which could fuse two
    tags' text together, e.g. a closing '</b>' immediately followed by the
    next line's word)."""
    return " ".join(line.strip() for line in html.splitlines() if line.strip())


def render_dashboard_html(app):
    body = """
<div class="verdict" id="verdict">Loading&hellip;</div>

<h2 class="section">Signal Path (24h)</h2>
<div class="sigpath" id="sigpath">
  <div class="stagerow">
    <div class="stage"><span class="n">01</span> ingest <b id="sp-ingested">&mdash;</b></div>
    <div class="stage"><span class="n">02</span> context <b id="sp-context">&mdash;</b>
      <span class="muted">bundle &rarr; redact</span></div>
    <div class="stage"><span class="n">03</span> enrich <b id="sp-enriched">&mdash;</b></div>
    <div class="stage"><span class="n">04</span> deliver <b id="sp-delivered">&mdash;</b></div>
  </div>
  <svg class="sigpath-svg" id="sigpath-svg"></svg>
  <div class="sigpath-tag" id="sp-shed">shed &mdash;</div>
  <div class="sigpath-tag raw" id="sp-raw">raw fallback &mdash;</div>
</div>

<h2 class="section">Invariants</h2>
<div class="chips">
  <div class="chip" id="chip-undelivered"><span class="label">Undelivered now</span>
    <span class="val" id="v-undelivered">&mdash;</span></div>
  <div class="chip" id="chip-enriched-rate"><span class="label">Enriched rate (24h)</span>
    <span class="val" id="v-enriched-rate">&mdash;</span></div>
  <div class="chip" id="chip-breaches"><span class="label">Deadline breaches (24h)</span>
    <span class="val" id="v-breaches">&mdash;</span></div>
  <div class="chip" id="chip-queue"><span class="label">Queue depth / max</span>
    <span class="val" id="v-queue">&mdash;</span></div>
</div>

<h2 class="section">Traffic (48h)</h2>
<div id="stripchart-wrap">
  <svg class="stripchart" id="stripchart" viewBox="0 -6 480 78" preserveAspectRatio="none"></svg>
  <div class="axis"><span>-48h</span><span>-24h</span><span>now</span></div>
  <p class="muted" id="stripchart-empty" style="display:none">no signals recorded in this window</p>
</div>

<h2 class="section">Volume &amp; Cost <span class="q">(24H)</span></h2>
<div class="rail">
  <div class="c3"><div class="label">Alerts</div><div class="value" id="v-ingested-24h">&mdash;</div>
    <div class="delta" id="delta-ingested"></div></div>
  <div class="c3"><div class="label">P95 added latency</div><div class="value" id="v-p95-latency">&mdash;</div>
    <div class="sub" id="sub-p95-latency"></div><div class="delta" id="delta-p95"></div></div>
  <div class="c3"><div class="label">Tokens</div><div class="value" id="v-tokens">&mdash;</div>
    <div class="sub" id="sub-tokens"></div></div>
  <div class="c3" id="cardrx"><div class="label">Redactions</div>
    <div class="value" id="v-redactions">&mdash;</div></div>
</div>
<div class="counters" id="vccnt"></div>

<h2 class="section">Plumbing Health</h2>
<div class="strip" id="health-strip"></div>

<h2 class="section">Patterns <span class="q">(24H)</span></h2>
<div class="grid2">
  <div><div class="label" style="margin-bottom:6px">Source</div><div class="barlist" id="bars-source"></div></div>
  <div><div class="label" style="margin-bottom:6px">Category</div><div class="barlist" id="bars-category"></div></div>
  <div><div class="label" style="margin-bottom:6px">Severity</div><div class="barlist" id="bars-severity"></div></div>
  <div><div class="label" style="margin-bottom:6px">Fail stage</div><div class="barlist" id="bars-failstage"></div></div>
</div>
<div style="margin-top:12px"><div class="label" style="margin-bottom:6px">Recurring signatures</div>
  <div class="barlist" id="signatures"></div></div>

<h2 class="section">Subjects <span class="q">(24H)</span></h2>
<div class="sjb">
  <div><div class="sl">Hosts</div><div id="hled"></div>
    <div class="counters" id="hcnt"></div></div>
  <div><div class="sl">Noisiest subjects</div><div class="barlist" id="ns"></div></div>
</div>
<div class="sg" id="sg" style="margin-top:20px">
  <div class="sl">Source &times; time (48h)</div>
</div>

<hr class="rule-full">
<h2 class="section">Recent Alerts</h2>
<div class="tablewrap wide"><table>
  <thead><tr><th>Time</th><th class="cs">Source</th><th>Subject</th><th>Sev</th>
    <th class="c2">Category</th><th>Outcome</th><th class="num">Latency</th>
    <th class="c2 num">Tokens</th></tr></thead>
  <tbody id="alerts-tbody"><tr><td colspan="8" class="muted">loading&hellip;</td></tr></tbody>
</table></div>
<footer class="foot">Nuncio &middot; read-only, unauthenticated by design &mdash; deploy behind your own network boundary</footer>
"""
    return _page_shell(app, "Nuncio", _minify_body(body), extra_js=_JS).encode()


# --- /alert/<key> drill-down ---

def _badge(value, cls_map, default="null"):
    if not value:
        return f'<span class="pill null">unknown</span>'
    cls = cls_map.get(value, default)
    return f'<span class="pill {cls}">{_esc(value)}</span>'


# "raw_and_enriched"/"raw_pending_enrich"/"raw_only_final" are historical
# outcome values from the retired raw_first delivery mode -- kept here only
# so an old DB row's drill-down page still renders a sensible badge.
_OUTCOME_CLASS = {
    "enriched": "enriched", "raw_and_enriched": "enriched",
    "raw": "raw", "raw_pending_enrich": "raw", "raw_only_final": "raw",
}

# assist_status -> pill tone: done (delivered) reads like an enriched
# success, failed reads like any other pipeline failure, deferred reads like
# a raw-fallback in flight, skipped/unset is the neutral "not used" null.
_ASSIST_CLASS = {"done": "enriched", "failed": "fail", "deferred": "raw", "skipped": "null"}


def render_alert_detail_html(app, key):
    """The transparency drill-down: "what exactly did we
    send to the model and why". Returns None if the key doesn't exist (the
    caller maps that to a 404) -- never raises on a missing/malformed row."""
    row = app.store.get_alert_detail(key)
    if row is None:
        return None

    private_cfg = (app.plane_info or {}).get("private", {})
    model = private_cfg.get("model") or "—"

    _NA = "—"  # em dash — used as plain text, not an HTML entity, so a
    # single uniform _esc() pass below is always correct (no double-escaping
    # to special-case).
    assist_status = row.get("assist_status")
    kv_rows = [
        ("Source", row.get("source") or _NA),
        ("Category", row.get("category") or _NA),
        ("Severity", row.get("severity") or _NA),
        ("Delivery mode", row.get("delivery_mode") or _NA),
        ("Plane / model", f"private / {model}"),
        ("Fail stage", row.get("fail_stage") or _NA),
        ("Latency (ingest→delivered)",
         f"{row['latency_ms']} ms" if row.get("latency_ms") is not None else _NA),
        ("LLM call time", f"{row['llm_ms']} ms" if row.get("llm_ms") is not None else _NA),
        ("Tokens in / out",
         f"{row.get('tokens_in') if row.get('tokens_in') is not None else _NA} / "
         f"{row.get('tokens_out') if row.get('tokens_out') is not None else _NA}"),
        ("Redaction findings", row.get("redaction_count") if row.get("redaction_count") is not None else 0),
        ("Bundle size", f"{row['bundle_bytes']} bytes" if row.get("bundle_bytes") is not None else _NA),
        ("Assist status", assist_status or _NA),
        ("Status", row.get("status") or _NA),
    ]
    kv_html = "".join(
        f"<dt>{_esc(str(label))}</dt><dd>{_esc(str(value))}</dd>"
        for label, value in kv_rows
    )

    outcome = row.get("outcome")
    outcome_badge = _badge(outcome, _OUTCOME_CLASS)

    def stage(n, title, text, extra_html=""):
        heading = (f'<h2 class="section stageblock"><span class="n">{n:02d}</span>'
                   f'&nbsp;&middot;&nbsp;{_esc(title)}{extra_html}</h2>')
        if not text:
            return heading + '<p class="muted">(none)</p>'
        return heading + f'<pre class="block">{_esc(text)}</pre>'

    assist_insight = row.get("assist_insight")
    assist_pill = f' {_badge(assist_status, _ASSIST_CLASS)}' if assist_status else ' <span class="pill null">unused</span>'
    if not assist_status or assist_status == "skipped":
        assist_stage_html = (
            f'<h2 class="section stageblock"><span class="n">04</span>'
            f'&nbsp;&middot;&nbsp;External assist insight (scrubbed){assist_pill}</h2>'
        )
        assist_stage_html += (
            f'<pre class="block">{_esc(assist_insight)}</pre>' if assist_insight
            else '<p class="muted">(assist plane not used for this alert)</p>'
        )
    else:
        assist_stage_html = stage(4, "External assist insight (scrubbed)", assist_insight, assist_pill)

    payload = row.get("payload") or ""
    headline_text = payload.splitlines()[0] if payload else key

    body = (
        '<a class="back" href="/">&larr; back to dashboard</a>'
        f'<p class="headline">{_esc(headline_text)} {outcome_badge}</p>'
        f'<p class="muted" style="font-family:var(--mono);font-size:11px;word-break:break-all">{_esc(key)}</p>'
        f'<div class="card"><dl class="kv">{kv_html}</dl></div>'
        + stage(1, "Raw alert (redacted, as delivered)", row.get("payload"))
        + stage(2, "Context bundle sent to the model (redacted)", row.get("bundle"))
        + stage(3, "Enrichment (delivered)", row.get("enrichment"))
        + assist_stage_html
    )
    return _page_shell(app, f"Alert {key}", body, extra_css=_DETAIL_CSS).encode()
