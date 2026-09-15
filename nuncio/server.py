"""Alert-enrichment Nuncio service — HTTP + queue + workers + maintenance.

stdlib-only HTTP service (no web framework -> lighter, more native image):
  POST /ingest/<source>  receive ONE native monitoring-tool payload, routed to
                 its registered SourceAdapter; persist-before-ACK each parsed
                 alert, enqueue for enrichment. Load-sheds when the queue is
                 full (persist only; the maintenance thread delivers it raw
                 at deadline).
  POST /ingest   back-compat/generic: uses payload["source"] if present, else
                 the configured default source.
                 Both ingest routes accept an optional `?severity=<critical|
                 warning|info|ok>` query param, applied ONLY when the
                 payload itself carries no usable severity (missing or
                 normalizes to "unknown") -- a payload-supplied severity
                 always wins, and an invalid value is silently ignored. For
                 fixed-body webhooks (watchtower, cifs-monitor) that cannot
                 add fields of their own; keeps severity deterministic-by-
                 configuration, never LLM-inferred.
  GET  /sources  registered source adapter names + per-source ingest counts.
  GET  /config.json  effective configuration, secrets masked.
  GET  /health   liveness -- 503 if any worker/maintenance thread has died.
  GET  /metrics  Prometheus text for scraping.
  GET  /              the web dashboard -- read-only, no auth.
  GET  /stats.json    dashboard counters + rates.
  GET  /alerts.json   recent alerts (the dashboard's table data).
  GET  /alert/<key>   per-alert transparency drill-down (redacted bundle, timings).
  GET  /logo.png      the dashboard's header logo asset.
  GET  /providers.json  provider registry listing (ids, redacted URLs, key
                  presence) -- secrets never included.
  GET  /providers/<id>/test  admin-gated live probe of one provider: a
                  static no-alert-data ping. 401/403 without X-Admin-Token.

A background maintenance thread is the never-lose safety net: it
re-delivers, as raw, any undelivered row older than the deadline -- covering
delivery failures (channel was down), load-shed overflow, queued-past-deadline
starvation, and a prior crash's leftovers (first pass = startup drain). Because
delivery is at-least-once, a rare maintenance/worker overlap yields a duplicate
push, never a lost alert.

This module reads NO environment variables -- all config parsing, validation,
and collaborator construction happens in `nuncio/config.py` (the composition
root); `python -m nuncio` (nuncio/__main__.py) wires the two together.
"""
import hmac
import itertools
import json
import logging
import queue
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from nuncio import __version__, sources
from nuncio.clients import CollectorHealth
from nuncio.deadline import Deadline
from nuncio.fingerprint import fingerprint
from nuncio.model import categorize, real_host
from nuncio.redactor import redact
from nuncio.semantic import distribution as _semantic_distribution
from nuncio.web import dashboard
from nuncio.web import settings as settings_ui

log = logging.getLogger("nuncio.server")

_RECEIVED = "received"
# Q2a: severity lanes for the priority work queue. Criticals always enrich
# first during bursts (the observed shed class was criticals drowning behind
# recoveries under FIFO); unknown joins warning (disposition treats it as a
# problem); anything unrecognized joins warning rather than starving.
_SEVERITY_PRIORITY = {"critical": 0, "warning": 1, "unknown": 1, "info": 2, "ok": 3}
# Phase 5.1: the only values `?severity=` on an ingest URL may set. Anything
# else (typo, unrecognized word, missing) is ignored, not errored -- a bad
# query param must never fail the ingest, only fail to override.
_VALID_INGEST_SEVERITIES = ("critical", "warning", "info", "ok")


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.ingested = 0
        self.delivered = {"enriched": 0, "raw": 0}
        self.failures = {}   # stage -> count
        self.duplicates = 0
        self.recovered = 0   # delivered by the maintenance safety net
        # Phase B BLOCKER 2b: a race the maintenance-cutoff fix (2a) already
        # closes for the common case -- this counts the rare remaining times
        # the fail-open delivery belt (Engine._deliver_enriched/_deliver_raw)
        # actually caught a would-be double delivery. Not a failure.
        self.duplicates_avoided = 0
        self.queue_depth = 0
        self.by_source = {}  # source name -> ingested count (transparency, GET /sources)
        # Batch C: assist-plane (nuncio.assist.AssistTrack) counters.
        self.assist_attempted = 0
        self.assist_ok = 0
        self.assist_failed = 0
        # Batch 2 item C: dead-letter purge counter -- rows permanently stuck
        # at status='received' (every maintenance retry exhausted) that got
        # deleted rather than retried forever.
        self.purged_stale_received = 0
        # Q2: alerts folded into a digest window instead of enriched
        # individually (status delivered_digested in the store).
        self.digested = 0
        # Deep-RCA budget pass: LLM calls abandoned at their hard wall-clock
        # bound (`Engine._call_bounded`'s TimeoutError branch -- the thread
        # leaks until the socket timeout, so this is the one signal that
        # distinguishes "LLM endpoint hung past its bound" from a plain
        # transport failure). The raw fallback watchdog.
        self.llm_abandoned = 0
        # Live reference to the engine's LLM circuit breaker (wired by App).
        # When set, the renderer emits its trip counter and state as gauges;
        # None (hand-built Metrics in tests) just omits the lines.
        self.breaker = None
        # P2: per-provider breaker map (wired by App like `breaker` above).
        # Rendered as labelled series; empty/None omits them.
        self.breakers = None
        # C4: ingest-storm trips/activity (wired by App via `storm_state`).
        self.storm = None

    def inc(self, attr, key=None, n=1):
        with self._lock:
            if key is None:
                setattr(self, attr, getattr(self, attr) + n)
            else:
                d = getattr(self, attr)
                d[key] = d.get(key, 0) + n

    def render(self):
        with self._lock:
            lines = [
                f"nuncio_ingested_total {self.ingested}",
                f"nuncio_duplicates_dropped_total {self.duplicates}",
                f"nuncio_recovered_total {self.recovered}",
                f"nuncio_duplicates_avoided_total {self.duplicates_avoided}",
                f"nuncio_queue_depth {self.queue_depth}",
            ]
            for outcome, n in self.delivered.items():
                lines.append(f'nuncio_delivered_total{{outcome="{outcome}"}} {n}')
            for stage, n in self.failures.items():
                lines.append(f'nuncio_failures_total{{stage="{stage}"}} {n}')
            for src, n in self.by_source.items():
                lines.append(f'nuncio_ingested_by_source_total{{source="{src}"}} {n}')
            lines.append(f"nuncio_assist_attempted_total {self.assist_attempted}")
            lines.append(f"nuncio_assist_ok_total {self.assist_ok}")
            lines.append(f"nuncio_assist_failed_total {self.assist_failed}")
            lines.append(f"nuncio_purged_stale_received_total {self.purged_stale_received}")
            lines.append(f"nuncio_llm_abandoned_total {self.llm_abandoned}")
            lines.append(f"nuncio_digested_total {self.digested}")
            if self.breaker is not None:
                lines.append(f"nuncio_llm_breaker_trips_total {self.breaker.trips}")
                for st in ("closed", "half_open", "open"):
                    on = 1 if self.breaker.state == st else 0
                    lines.append(f'nuncio_llm_breaker_state{{state="{st}"}} {on}')
            # C4: ingest-storm telemetry -- trips (lifetime count) and
            # whether the storm-mode behaviour is currently active (gauge,
            # so it returns to 0 the moment the storm clears).
            try:
                st = self.storm
                if st is not None:
                    lines.append(f"nuncio_storm_entered_total {st.get('entered', 0)}")
                    lines.append(f"nuncio_storm_active {1 if st.get('active') else 0}")
            except Exception:
                pass
            # P2: labelled per-provider series alongside the legacy
            # unlabelled ones above (which track the ACTIVE breaker -- see
            # build_app/apply_changes re-pointing). Same object may appear
            # in both when a provider is selected; that duplication is
            # deliberate (existing rules keep working post-cutover).
            for pid in sorted((self.breakers or {})):
                br = self.breakers[pid]
                try:
                    lines.append(f'nuncio_llm_breaker_trips_total{{provider="{pid}"}} {br.trips}')
                    for st in ("closed", "half_open", "open"):
                        on = 1 if br.state == st else 0
                        lines.append(f'nuncio_llm_breaker_state{{provider="{pid}",state="{st}"}} {on}')
                except Exception:
                    continue
            # C1: semantic-similarity distribution over recently scored
            # correlated pairs (best-effort operational telemetry -- answers
            # "is the Jaccard signal worth upgrading to embeddings?").
            try:
                dist = _semantic_distribution()
                lines.append(f"nuncio_semantic_pairs_observed_total {dist['total']}")
                lines.append(f"nuncio_semantic_similarity_p50 {dist['p50']:.3f}")
                lines.append(f"nuncio_semantic_similarity_p90 {dist['p90']:.3f}")
                lines.append(f"nuncio_semantic_similarity_max {dist['max']:.3f}")
            except Exception:
                pass
        return "\n".join(lines) + "\n"


class App:
    def __init__(self, engine, store, metrics, budget_s, concurrency, queue_max,
                 clock, wall_clock=time.time, maint_interval=20.0, maint_margin=10.0,
                 retention_s=30 * 86400, token=None, default_source="generic",
                 config_json=b"{}",
                 # Dashboard context. All optional/defaulted so existing
                 # App(...) call sites (tests, config.py) keep working
                 # unchanged as this grows.
                 version=__version__, collector_impls=None, collector_health=None,
                 plane_info=None, delivery_adapters=None, logo_bytes=b"",
                 favicon_data_uri="", admin_token=None,
                 # Phase B: the full-depth alert budget (see nuncio.config's
                 # `effective_full_budget_s` -- always >= budget_s, computed
                 # with a max()+warning, NEVER a startup ConfigError). Defaults
                 # to the same 60.0 as NUNCIO_FULL_BUDGET_S's own schema
                 # default so a hand-built App (tests) that doesn't pass this
                 # still gets a sane, budget_s-dominant value in the common
                  # case (budget_s <= 60).
                  full_budget_s=60.0,
                  # P1: whether the private plane is currently trusted.
                  # Captured per-alert at ingest (below) into the queue
                  # tuple -- the worker/engine never re-resolve it, so a
                  # live selector flip can't re-route an in-flight alert.
                  # config.build_app sets this from the resolved registry;
                  # hand-built Apps default to untrusted (zero behavior
                  # change).
                  private_trusted=False,
                  # Q2: same-fingerprint generic info-severity coalescing
                  # window (NUNCIO_DIGEST_WINDOW_S). 0.0 disables -- a
                  # hand-built App that doesn't pass this behaves exactly
                  # like before (every alert enriched individually).
                  digest_window_s=0.0):
        self.engine = engine
        self.store = store
        self.metrics = metrics
        # C4: ingest-storm state (defined before the metrics wiring below,
        # which references it; see _bump_storm/in_storm for the model).
        self._storm_rate_ts = deque()
        self.storm_state = {"entered": 0, "active": False}
        # Wire the breaker into the metrics renderer (live state/trips gauge
        # on /metrics). Guarded so a fake Metrics in tests stays untouched.
        if self.metrics is not None and hasattr(self.metrics, "breaker"):
            self.metrics.breaker = getattr(engine, "breaker", None)
        # P2: the per-provider breaker map for labelled series (same guard).
        if self.metrics is not None and hasattr(self.metrics, "breakers"):
            self.metrics.breakers = getattr(engine, "provider_breakers", None) or None
        # C4: storm state for /metrics transparency (same guard).
        if self.metrics is not None and hasattr(self.metrics, "storm"):
            self.metrics.storm = self.storm_state
        self.budget_s = budget_s
        self.full_budget_s = full_budget_s
        self.private_trusted = private_trusted
        self.digest_window_s = digest_window_s or 0.0
        # Q2 digest state: fingerprint -> {"first_at", "keys", "lines",
        # "service", "host", "category"}. In-memory ONLY (never persisted):
        # a restart loses open windows, and the next arrival starts a fresh
        # one (fail-open -- the first notice always goes out immediately).
        # RLock: sweeps emit via self.ingest, which re-enters this lock.
        self._digest = {}
        self._digest_lock = threading.RLock()
        self.clock = clock
        self.wall_clock = wall_clock
        self.maint_interval = maint_interval
        self.maint_margin = maint_margin
        self.retention_s = retention_s
        self.token = token  # optional shared secret required on /ingest*
        self.default_source = default_source
        self.config_json = config_json  # effective config, secrets masked (GET /config.json)
        self.router = None  # optionally set by config.py; consumed by the engine (see nuncio/config.py's
                             # build_app), not by the HTTP layer -- kept here only for dashboard/settings transparency
        self.queue_max = queue_max
        self.concurrency = concurrency
        self.version = version
        self.start_wall = wall_clock()  # dashboard uptime_s
        self.collector_impls = collector_impls or {"logs": "null", "containers": "null", "metrics": "null"}
        self.collector_health = collector_health if collector_health is not None else CollectorHealth()
        self.plane_info = plane_info or {"private": {"model": None}, "knowledge": {"enabled": False}}
        self.delivery_adapters = delivery_adapters or []
        self.logo_bytes = logo_bytes
        self.favicon_data_uri = favicon_data_uri
        self.admin_token = admin_token  # optional shared secret gating POST /settings
        # Settings-screen bookkeeping. `settings`/`boot_effective` are
        # normally populated by config.py's build_app() (the composition
        # root); left None/empty here so a hand-built App (tests) still
        # works, with the settings screen simply reporting "not configured".
        self.settings = None
        self.boot_effective = {}
        # Q2a: priority queue (severity lane, FIFO sequence within a lane).
        # put_nowait/get/qsize/task_done/Full semantics are identical to
        # queue.Queue; only the ORDER changes. The sequence counter makes
        # every item unique so the queue never compares payload dicts.
        self.q = queue.PriorityQueue(maxsize=queue_max)
        self._qseq = itertools.count()
        # Batch 2 item C: in-memory per-key backoff for the maintenance
        # sweep -- key -> (next_retry_at, attempts). No schema change (this
        # is deliberately NOT persisted: on restart every key is retried
        # immediately again, which is fine -- the backoff only protects a
        # single long-running process from hammering a channel that's down).
        self._maint_backoff = {}
        self._maint_pass_count = 0
        self._threads = []
        for _ in range(concurrency):
            self._spawn(self._worker)
        self._spawn(self._maintenance)

    def _spawn(self, target):
        t = threading.Thread(target=target, daemon=True)
        t.start()
        self._threads.append(t)

    def healthy(self):
        return all(t.is_alive() for t in self._threads)

    def ingest(self, source_name, payload, headers=None, default_severity=None):
        """persist-before-ACK, once per ParsedAlert the adapter produces.
        Returns an HTTP status code:
        200 = persisted (ACK; includes duplicates and 0-alert batches), 400 =
        permanently unparseable (do not retry), 404 = unknown source, 500 =
        persist failed for at least one alert (RETRY -- the store couldn't
        fsync)."""
        headers = headers or {}
        if not isinstance(payload, dict):
            return 400
        adapter = sources.get(source_name)
        if adapter is None:
            return 404
        try:
            parsed = adapter.parse(payload, headers)
        except Exception:
            self.metrics.inc("failures", "parse")
            return 400
        if not parsed:
            return 200  # legitimate 0-alert batch -- nothing to persist, nothing lost
        # `?severity=<critical|warning|info|ok>` ingest-URL default (Phase 5.1):
        # a config-supplied fallback for dumb webhooks that cannot add fields
        # of their own (watchtower's fixed shoutrrr JSON body, cifs-monitor's
        # curl POST). Applied ONLY when the adapter couldn't determine a
        # severity from the payload itself (severity missing/falsy or the
        # normalize_severity() "unknown" catch-all) -- a payload-supplied
        # severity always wins, and an invalid/unrecognized query value is
        # silently ignored (falls through to the existing unknown/LLM-infer
        # path). This keeps severity deterministic-by-configuration, never
        # LLM-inferred -- see the determinism doctrine.
        if default_severity in _VALID_INGEST_SEVERITIES:
            for pa in parsed:
                if not isinstance(pa.alert, dict):
                    continue
                current = pa.alert.get("severity")
                if not current or current == "unknown":
                    pa.alert["severity"] = default_severity
        status = 200
        for pa in parsed:
            try:
                raw = redact(pa.raw_text)[0]  # no secret at rest / in the queued raw
            except Exception:
                raw = pa.raw_text
            mode = getattr(self.engine, "mode", "enriched")
            # The alert's OWN metadata, recorded here (not later by the
            # engine) so even a load-shed row the engine never sees still
            # shows up correctly on the dashboard's by-source/by-category/
            # by-severity breakdowns. category falls back to core
            # categorize() when the adapter didn't supply one; best-effort
            # (never blocks persist-before-ACK on a categorize() bug).
            try:
                category = pa.alert.get("category") or categorize(pa.alert)
            except Exception:
                category = None
            severity = pa.alert.get("severity") if isinstance(pa.alert, dict) else None
            # Subject metadata -- same isinstance guard as severity above (a
            # non-dict alert must never raise here and block persist-before-ACK).
            # host is stored as the REAL host verbatim (real_host() only
            # applies the placeholder guard -- "-"/blank/non-alnum persists
            # as NULL) and deliberately NOT canonicalized: canonicalization
            # (nuncio.model.canonical_host) happens at COMPARE time on both
            # sides in nuncio.correlate, so a later NUNCIO_HOST_DOMAINS
            # change applies retroactively to already-stored rows.
            host = real_host(pa.alert.get("host")) if isinstance(pa.alert, dict) else None
            service = pa.alert.get("service") if isinstance(pa.alert, dict) else None
            # Best-effort fingerprint, computed in its OWN try/except so a
            # fingerprinting bug can never block persist-before-ACK.
            try:
                fp = fingerprint(pa.alert)
            except Exception:
                fp = None
            try:
                newly = self.store.persist(pa.key, raw, mode=mode, source=source_name,
                                            category=category, severity=severity,
                                            fingerprint=fp, host=host,
                                            service=service)  # fsync'd before we return
            except Exception:
                self.metrics.inc("failures", "persist")
                status = 500  # source should retry the whole batch
                continue
            self.metrics.inc("ingested")
            self.metrics.inc("by_source", source_name)
            if not newly:
                self.metrics.inc("duplicates")
                continue  # duplicate -- already handled/queued
            # C4: record this ingest against the storm rate tracker (after
            # the duplicate gate -- only genuinely-new alerts count).
            try:
                self._bump_storm(self.wall_clock())
            except Exception:
                pass
            # Q2 digest: a generic info/ok notice inside an open window is
            # folded into the digest (status delivered_digested) instead of
            # queued for its own enrichment. The FIRST notice of a window
            # always takes the normal path below (fail-open). Criticals and
            # warnings never digest -- only quiet severities coalesce.
            if self._maybe_digest(source_name, pa.key, raw, mode, severity,
                                  host):
                continue
            # BLOCKER 1 (Phase B): `depth` is captured HERE, at ingest, and
            # the Deadline is built from the MATCHING budget for that depth
            # -- `full_budget_s` for a full-depth alert, `budget_s`
            # otherwise. Mirrors `mode`'s own "captured at ingest, rides the
            # queue tuple" discipline (see the comment below) for exactly
            # the same reason: a live NUNCIO_ENRICH_DEPTH flip mid-flight must
            # never re-route an alert that's already committed to a budget --
            # and, critically, a full-depth alert built with the SHORT
            # `budget_s` Deadline would silently run its 2-call pipeline
            # under 30s instead of 60s (the bug this fixes).
            depth = getattr(self.engine, "depth", "full")
            # Q2b: recovery notices skip deep RCA -- the disposition gate
            # discards cause/checks for ok AFTER the LLM runs, so a full-depth
            # 2-call pipeline on an ok alert is pure waste. Single call keeps
            # the summary ("Resolved at ... after ...").
            if severity == "ok":
                depth = "low"
            # C4: storm mode -- rate tripped, so non-critical problem alerts
            # also take the cheap single-call path (criticals always stay
            # full; they queue first under Q2a anyway).
            if severity != "critical" and self.in_storm():
                depth = "low"
            # P1: capture trust HERE, at ingest, into the queue tuple (same
            # discipline as mode/depth above). For a trusted alert also fork
            # the UNREDACTED raw text: `raw` (queued below) is always the
            # redacted form (persist/audit-safe); `raw_full` rides the tuple
            # in memory only and never touches the store.
            # P1/review: ALSO capture the provider id this alert trusted
            # under, so Engine.process can fail closed if a live selector
            # flip re-points the wire client mid-flight (an alert trusted
            # under provider A must never be sent raw to a now-selected
            # provider B) -- see Engine.process' choke point.
            trusted = bool(self.private_trusted)
            raw_full = pa.raw_text if (trusted and isinstance(pa.raw_text, str)) else None
            provider_at_ingest = getattr(self.engine, "provider_id", None) if trusted else None
            deadline = Deadline(self.full_budget_s if depth == "full" else self.budget_s, clock=self.clock)
            try:
                # `mode` rides the queue tuple (not re-read from self.engine.mode
                # by the worker) so a live settings-screen mode flip mid-flight
                # can never mis-route an in-flight alert -- see config.py's
                # apply_changes' docstring for the full reasoning. This
                # applies to `bypass` exactly like `enriched` -- bypass rides
                # the same persist->queue->worker machinery rather than being
                # delivered from this ingest thread, so the never-lose
                # invariant (persist-before-ACK, load-shed just leaves the
                # row persisted for the maintenance safety net) is identical
                # for every mode.
                # Q2a: (lane, sequence) ordering prefix -- the worker strips
                # it; depth/mode keep their capture-at-ingest discipline.
                # P1 appends (raw_full, trusted): the unredacted raw text
                # (memory-only, trusted alerts only) and the trust flag.
                prio = _SEVERITY_PRIORITY.get(severity or "unknown", 1)
                self.q.put_nowait((prio, next(self._qseq), pa.key, pa.alert, raw, raw_full,
                                   deadline, mode, depth, trusted, provider_at_ingest))
                self.metrics.queue_depth = self.q.qsize()
            except queue.Full:
                # load-shed: leave it persisted; the maintenance thread delivers
                # it raw at its deadline (does NOT block this handler).
                self.metrics.inc("failures", "queue")
        # Q2: emit any digest windows this batch closed out. Best-effort and
        # self-isolating (_emit_digest never raises); a quiet period with no
        # ingest traffic is covered by the maintenance pass instead. A sweep
        # failure must never change this batch's persist-before-ACK status.
        try:
            self._sweep_digests()
        except Exception:
            log.warning("digest sweep failed", exc_info=True)
        return status

    def _maybe_digest(self, source_name, key, raw, mode, severity, host):
        """Q2c coalescing decision for one freshly-persisted alert. Returns
        True when the alert was folded into its digest window (status now
        delivered_digested -- the caller must NOT queue it). Returns False
        for the first notice of a window and for everything digest-ineligible,
        which all take the normal path.

        Grouping key is (source, severity, host) -- deliberately NOT the
        fingerprint: the observed burst class is heterogeneous services
        flapping at once (a monitor sweep), which shares nothing
        fingerprint-stable. Eligibility is deliberately narrow: generic
        source, info/ok severity, enriched mode. A critical/warning or
        failure-marked item always alerts immediately. Held rows are
        terminally recorded, so a restart mid-window loses nothing that
        wasn't already announced by the window's first notice (fail-open)."""
        window = self.digest_window_s or 0
        if not (window > 0 and source_name == "generic"
                and severity in ("info", "ok") and mode == "enriched"):
            return False
        group = (source_name, severity, host)
        now = self.wall_clock()
        with self._digest_lock:
            due = self._sweep_digests_locked(now)
            ent = self._digest.get(group)
            _first = (raw or "").strip().splitlines()
            _line = (_first[0][:160] if _first else "(empty)")
            if ent is None:
                # Window opens with THIS notice. It takes the normal path
                # (delivered individually -- fail-open) but is counted and
                # remembered so the digest's "N notices" summary includes it
                # and the earliest text isn't lost.
                ent = {"first_at": now, "keys": [key], "lines": [_line],
                       "host": host, "severity": severity}
                self._digest[group] = ent
                fresh = True
            else:
                fresh = False
                if len(ent["keys"]) < self._DIGEST_MAX_KEYS:
                    ent["keys"].append(key)
                if len(ent["lines"]) < self._DIGEST_MAX_LINES:
                    ent["lines"].append(_line)
        for _expired_group, expired in due:
            self._emit_digest(expired)
        if fresh:
            return False
        try:
            held = self.store.mark_digested(key)
        except Exception:
            held = False
        if not held:
            # CAS lost -- the row already moved on (worker/maintenance won a
            # race). Fall through to the normal path; the worker's
            # status != received guard makes that a safe no-op.
            return False
        self.metrics.inc("digested")
        return True

    def _sweep_digests_locked(self, now):
        """Pop expired windows (and the oldest window past the group cap).
        Caller holds _digest_lock. Returns [(group, entry)] for the caller
        to emit AFTER releasing the lock."""
        window = self.digest_window_s or 0
        if window <= 0 or not self._digest:
            return []
        due = [(group, ent) for group, ent in self._digest.items()
               if now - ent["first_at"] >= window]
        for group, _ent in due:
            del self._digest[group]
        if len(self._digest) >= self._DIGEST_MAX_FPS:
            oldest = min(self._digest, key=lambda k: self._digest[k]["first_at"])
            due.append((oldest, self._digest.pop(oldest)))
        return due

    def _sweep_digests(self):
        """Emit all expired digest windows. Called at the ingest tail and
        once per maintenance pass; never raises (_emit_digest never raises)."""
        now = self.wall_clock()
        with self._digest_lock:
            due = self._sweep_digests_locked(now)
        for _expired_group, expired in due:
            self._emit_digest(expired)

    def _emit_digest(self, entry):
        """Persist + ingest ONE digest alert for a closed window. Best-effort
        throughout: failures here must never break the ingest path that
        triggered the sweep (held rows are already terminally recorded, and
        the window's first notice already went out). The digest re-enters
        ingest as an ordinary generic notice (fresh window if one opens)."""
        try:
            keys = entry.get("keys") or []
            if not keys:
                return
            lines = entry.get("lines") or []
            body = [f"{len(keys)} similar notices coalesced ({entry.get('severity') or 'info'})"]
            body += [f"- {ln}" for ln in lines]
            if len(keys) > len(lines):
                body.append(f"(+{len(keys) - len(lines)} more)")
            payload = {"message": "\n".join(body), "severity": entry.get("severity") or "info"}
            if entry.get("host"):
                payload["host"] = entry["host"]
            try:
                self.ingest("generic", payload)
            except Exception:
                log.warning("digest emit failed", exc_info=True)
        except Exception:
            log.warning("digest emit failed", exc_info=True)

    def _worker(self):
        while True:
            _prio, _seq, key, alert, raw, raw_full, deadline, mode, depth, trusted, provider_at_ingest = self.q.get()
            try:
                status = self.store.get_status(key)
                # A non-'received' status here means a prior pass (or
                # maintenance) already finished this row -- skip, don't
                # reprocess it.
                if status != _RECEIVED:
                    continue
                if deadline.expired():
                    self.metrics.inc("failures", "queue")
                    if mode == "bypass":
                        # bypass has nothing to time out on -- still run it
                        # through the normal path rather than the generic
                        # deadline-expired raw fallback.
                        outcome = self.engine.process(key, alert, raw, deadline=deadline, mode=mode,
                                                      depth=depth, trusted=trusted, raw_full=raw_full,
                                                      provider_at_ingest=provider_at_ingest)
                    else:
                        outcome = self.engine._deliver_raw(key, raw, fail_stage="deadline")
                else:
                    outcome = self.engine.process(key, alert, raw, deadline=deadline, mode=mode,
                                                  depth=depth, trusted=trusted, raw_full=raw_full,
                                                  provider_at_ingest=provider_at_ingest)
                if outcome in ("enriched", "raw"):
                    self.metrics.inc("delivered", outcome)
                elif outcome == "delivery_failed":
                    self.metrics.inc("failures", "delivery")
                elif outcome == "skipped_duplicate":
                    self.metrics.inc("duplicates_avoided")
            except Exception:
                self.metrics.inc("failures", "worker")
            finally:
                self.metrics.queue_depth = self.q.qsize()
                self.q.task_done()

    # Bounds one pass's undelivered-row sweep so a huge backlog can't starve
    # this same pass's other duties (assist sweep, purge_delivered, the
    # dead-letter purge, the periodic WAL checkpoint) -- see item C.
    _MAINT_SWEEP_LIMIT = 50
    # Per-key maintenance-delivery backoff: exponential, capped at 1h.
    _MAINT_BACKOFF_BASE_S = 30.0
    _MAINT_BACKOFF_CAP_S = 3600.0
    # PRAGMA wal_checkpoint(TRUNCATE) roughly once every 10 passes.
    _MAINT_WAL_CHECKPOINT_EVERY = 10
    # A row still at status='received' this long has exhausted every retry
    # the sweep offers and is permanently poisoned, not in-flight.
    _MAINT_STALE_RECEIVED_S = 7 * 86400
    # Q2 digest bounds: max open windows (fingerprints) and max item lines
    # retained per window. Both bound memory only -- overflow emits the
    # oldest window early rather than dropping anything.
    _DIGEST_MAX_FPS = 512
    _DIGEST_MAX_LINES = 50
    _DIGEST_MAX_KEYS = 128
    # C4 storm-mode constants. Trips when >= _STORM_RATE alerts land within a
    # 60s span; stays active for _STORM_ACTIVE_S after the last trip. Not
    # settings knobs (deliberately CONNECTED to Q2's digest+priority work:
    # this is the same observed sweep-burst class, and the cheap-path is the
    # second lever on top of Q2a's ordering). /metrics exposes the state.
    _STORM_WINDOW_S = 60.0
    _STORM_RATE = 20
    _STORM_ACTIVE_S = 300.0

    def _bump_storm(self, now):
        """Record one ingest at `now` (wall clock) and update storm state.
        Guarded by the digest lock (same fast path, RLock -- reentrant from
        digest emit). Best-effort and self-isolating: a storm tracker bug
        must never break persist-before-ACK (wrapped by callers)."""
        try:
            with self._digest_lock:
                cutoff = now - self._STORM_WINDOW_S
                self._storm_rate_ts.append(now)
                while self._storm_rate_ts and self._storm_rate_ts[0] < cutoff:
                    self._storm_rate_ts.popleft()
                if len(self._storm_rate_ts) >= self._STORM_RATE:
                    self.storm_state["entered"] += 1
                    self.storm_state["active"] = True
                    self.storm_state["until"] = now + self._STORM_ACTIVE_S
                if self.storm_state.get("active") and now >= self.storm_state.get("until", 0.0):
                    self.storm_state["active"] = False
        except Exception:
            pass

    def in_storm(self, now=None):
        """True while storm mode is active (rate tripped within the active
        window). Thread-safe read via the digest lock. Never raises."""
        try:
            now = self.wall_clock() if now is None else now
            with self._digest_lock:
                if self.storm_state.get("active") and now < self.storm_state.get("until", 0.0):
                    return True
                if self.storm_state.get("active"):
                    self.storm_state["active"] = False
            return False
        except Exception:
            return False

    def _maint_backoff_skip(self, key, now):
        until = self._maint_backoff.get(key)
        return until is not None and now < until[0]

    def _maint_backoff_bump(self, key, now):
        _, attempts = self._maint_backoff.get(key, (0.0, 0))
        attempts += 1
        delay = min(self._MAINT_BACKOFF_CAP_S, self._MAINT_BACKOFF_BASE_S * (2 ** (attempts - 1)))
        self._maint_backoff[key] = (now + delay, attempts)

    def _maint_backoff_clear(self, key):
        self._maint_backoff.pop(key, None)

    def _maintenance(self):
        """Safety net: deliver-as-raw any undelivered row past its deadline.
        First pass = startup drain -- uses an age-0 cutoff (ALL `received`
        rows, regardless of age) so a prior crash's leftovers go out
        immediately rather than waiting out the normal budget_s+maint_margin
        aging window; every subsequent pass reverts to the aged cutoff so it
        doesn't race live in-flight alerts every cycle. Runs forever.

        BLOCKER 2a (Phase B): the aged cutoff uses
        `max(budget_s, full_budget_s) + maint_margin`, NOT `budget_s` alone
        -- a full-depth alert legitimately running close to its (longer)
        `full_budget_s` deadline must never look "stale" to this sweep while
        the worker is still legitimately processing it; using the shorter
        `budget_s` here would let maintenance deliver a raw copy WHILE the
        worker is mid-flight on the same key, i.e. a double delivery. The
        BLOCKER 2b belt in `Engine._deliver_enriched`/`_deliver_raw` is the
        second, independent line of defense for the same race (this cutoff
        fix removes the common case; the belt catches anything this cutoff
        alone can't, e.g. a worker that's unusually slow for reasons outside
        its own deadline accounting).

        Batch 2 item C hardening: every duty below is isolated in its own
        try/except so a failure in one (e.g. the undelivered-rows fetch
        itself, not just a single poisoned row) can never starve the others
        in the same pass. A repeatedly-failing key backs off exponentially
        instead of being retried every single pass; rows dead-lettered at
        'received' past a week are purged with a warning; the WAL is
        checkpointed periodically."""
        first_pass = True
        while True:
            self._maint_pass_count += 1
            if first_pass:
                cutoff = self.wall_clock()
                first_pass = False
            else:
                cutoff = self.wall_clock() - (max(self.budget_s, self.full_budget_s) + self.maint_margin)

            try:
                rows = self.store.undelivered_older_than(cutoff, limit=self._MAINT_SWEEP_LIMIT)
            except Exception:
                rows = ()
                self.metrics.inc("failures", "maintenance")

            now = self.wall_clock()
            for key, raw in rows:
                # Per-row isolation: undelivered_older_than() returns rows
                # OLDEST-FIRST, so a single poisoned row that always raises
                # must never abort the rest of the pass -- else that same
                # row re-fails every cycle and permanently stalls recovery
                # of every row after it. Mirrors Engine.drain_raw's
                # try/except:continue.
                if self._maint_backoff_skip(key, now):
                    continue
                try:
                    outcome = self.engine._deliver_raw(key, raw, fail_stage="queue")
                    if outcome == "raw":
                        self.metrics.inc("recovered")
                        self._maint_backoff_clear(key)
                    elif outcome == "skipped_duplicate":
                        # BLOCKER 2b belt fired -- the worker already (or
                        # concurrently) delivered this key; not a failure,
                        # not a recovery, just a race avoided.
                        self.metrics.inc("duplicates_avoided")
                        self._maint_backoff_clear(key)
                    else:
                        self._maint_backoff_bump(key, now)
                except Exception:
                    self.metrics.inc("failures", "maintenance")
                    self._maint_backoff_bump(key, now)
                    continue

            # Batch C: restart/orphan sweep for the assist plane's rich-
            # delivery leg -- a row stuck at assist_status='deferred' past
            # its own timeout (e.g. the process crashed with items still on
            # the assist worker's in-memory queue). A no-op when the assist
            # plane is disabled or has nothing pending. Isolated so a
            # failure here (or above, fetching rows) never blocks the
            # duties below.
            # Q2: emit expired digest windows (own isolation -- a digest bug
            # must never starve the other duties).
            try:
                self._sweep_digests()
            except Exception:
                self.metrics.inc("failures", "maintenance")
            assist = getattr(self.engine, "assist", None)
            if assist is not None:
                try:
                    assist.sweep_orphans()
                except Exception:
                    self.metrics.inc("failures", "maintenance")

            try:
                self.store.purge_delivered(self.wall_clock() - self.retention_s)
            except Exception:
                self.metrics.inc("failures", "maintenance")

            try:
                purged = self.store.purge_stale_received(self.wall_clock() - self._MAINT_STALE_RECEIVED_S)
                if purged:
                    log.warning(
                        "purged %d alert(s) permanently stuck at status='received' "
                        "(older than %ds -- every maintenance retry exhausted)",
                        purged, self._MAINT_STALE_RECEIVED_S,
                    )
                    self.metrics.inc("purged_stale_received", n=purged)
            except Exception:
                self.metrics.inc("failures", "maintenance")

            if self._maint_pass_count % self._MAINT_WAL_CHECKPOINT_EVERY == 0:
                try:
                    self.store.wal_checkpoint()
                except Exception:
                    self.metrics.inc("failures", "maintenance")

            time.sleep(self.maint_interval)


def _render_collector_empty_streaks(app):
    """Prometheus gauge lines for the gatherer's per-collector
    consecutive-empty streaks (Batch 2 item F -- see
    nuncio.gatherer.Gatherer.empty_streaks). A gauge, not a counter: it can
    go back down to 0 the moment a collector starts returning real data
    again, which is exactly the signal worth alerting on staying high.
    Empty string when no gatherer is wired (Level A, or a test double)."""
    gatherer = getattr(getattr(app, "engine", None), "gatherer", None)
    if gatherer is None:
        return ""
    lines = [
        f'nuncio_collector_empty_streak{{collector="{name}"}} {n}'
        for name, n in gatherer.empty_streaks().items()
    ]
    return ("\n".join(lines) + "\n") if lines else ""


def _handler_factory(app):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body=b"", ctype="text/plain"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            split = urlsplit(self.path)
            path = split.path
            if path == "/health":
                self._send(200, b"ok") if app.healthy() else self._send(503, b"unhealthy")
            elif path == "/metrics":
                self._send(200, (app.metrics.render() + _render_collector_empty_streaks(app)).encode())
            elif path == "/sources":
                body = json.dumps({
                    "registered": sources.names(),
                    "ingested_by_source": app.metrics.by_source,
                }).encode()
                self._send(200, body, ctype="application/json")
            elif path == "/config.json":
                self._send(200, app.config_json, ctype="application/json")
            # --- dashboard -- all GET, read-only ---
            elif path == "/":
                self._send(200, dashboard.render_dashboard_html(app), ctype="text/html; charset=utf-8")
            elif path == "/stats.json":
                self._send(200, dashboard.render_stats_json(app), ctype="application/json")
            elif path == "/alerts.json":
                qs = parse_qs(split.query)
                limit = qs.get("limit", ["50"])[0]
                source = qs.get("source", [None])[0]
                outcome = qs.get("outcome", [None])[0]
                body = dashboard.render_alerts_json(app, limit=limit, source=source, outcome=outcome)
                self._send(200, body, ctype="application/json")
            elif path.startswith("/alert/"):
                key = unquote(path[len("/alert/"):])
                if not key:
                    self._send(404, b"not found")
                    return
                html = dashboard.render_alert_detail_html(app, key)
                if html is None:
                    self._send(404, b"alert not found")
                else:
                    self._send(200, html, ctype="text/html; charset=utf-8")
            elif path == "/logo.png":
                if app.logo_bytes:
                    self._send(200, app.logo_bytes, ctype="image/png")
                else:
                    self._send(404, b"not found")
            elif path == "/settings":
                self._send(200, settings_ui.render_settings_html(app), ctype="text/html; charset=utf-8")
            elif path == "/settings.json":
                self._send(200, settings_ui.render_settings_json(app), ctype="application/json")
            elif path == "/providers.json":
                from nuncio import config as _config
                body = json.dumps(_config.providers_list_view(app.settings)).encode()
                self._send(200, body, ctype="application/json")
            elif path == "/feedback.json":
                body = json.dumps(app.store.feedback_summary()).encode()
                self._send(200, body, ctype="application/json")
            elif path.startswith("/providers/") and path.endswith("/test"):
                self._do_provider_test(app, path[len("/providers/"):-len("/test")])
            else:
                self._send(404, b"not found")

        def do_POST(self):
            if self.path == "/settings":
                self._do_post_settings()
                return
            if self.path == "/feedback":
                self._do_post_feedback()
                return
            split = urlsplit(self.path)
            path = split.path
            if not (path == "/ingest" or path.startswith("/ingest/")):
                self._send(404, b"not found")
                return
            if app.token:
                xauth_ok = hmac.compare_digest(self.headers.get("X-Auth-Token", "") or "", app.token)
                auth_header = self.headers.get("Authorization", "") or ""
                bearer_ok = False
                if auth_header[:7].lower() == "bearer ":
                    bearer_ok = hmac.compare_digest(auth_header[7:], app.token)
                if not (xauth_ok or bearer_ok):
                    log.warning("ingest auth failed: path=%s", path)
                    app.metrics.inc("failures", "auth")
                    self._send(401, b"unauthorized")
                    return
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length <= 0 or length > 1_000_000:  # bound the body
                    self._send(400, b"bad request")
                    return
                payload = json.loads(self.rfile.read(length).decode())
            except Exception:
                self._send(400, b"bad request")
                return
            if path.startswith("/ingest/"):
                source_name = path[len("/ingest/"):]
            else:
                source_name = (payload.get("source") if isinstance(payload, dict) else None) \
                    or app.default_source
            # `?severity=` -- see App.ingest's docstring/comment for the
            # scoped, payload-wins precedence; unrecognized values are
            # deliberately NOT validated here, only in App.ingest, so this
            # HTTP layer stays a thin, mechanical query-string pass-through.
            severity_param = parse_qs(split.query).get("severity", [None])[0]
            try:
                status = app.ingest(source_name, payload, dict(self.headers),
                                     default_severity=severity_param)
            except Exception:
                status = 500
            if status == 200:
                body = b"ok"
            elif status == 404:
                body = b"unknown source"
            else:
                body = b"error"
            self._send(status, body)

        def _do_post_settings(self):
            # Body-size bound is enforced INSIDE handle_post (413) against
            # the already-read bytes, but Content-Length is checked first so
            # a hostile/huge declared length is never even read into memory.
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except Exception:
                length = 0
            if length <= 0 or length > settings_ui.MAX_BODY_BYTES:
                self._send(413 if length > settings_ui.MAX_BODY_BYTES else 400, b'{"error": "bad request"}',
                           ctype="application/json")
                return
            body_bytes = self.rfile.read(length)
            # self.headers (an email.message.Message) rather than dict(self.headers)
            # -- header LOOKUP must be case-insensitive (HTTP header names are),
            # and Message.get() is; a plain dict built from it is not.
            status, result = settings_ui.handle_post(app, body_bytes, self.headers)
            self._send(status, json.dumps(result).encode(), ctype="application/json")

        def _do_post_feedback(self):
            """C6: admin-gated operator feedback (confirm_root | split | merge).
            Same fail-closed auth as /settings; records best-effort into the
            feedback table and lets the correction cache pick it up within the
            hour. Body shape: {"key": ..., "action": ..., "ref_key": optional}."""
            ok, code = settings_ui.check_admin_token(app, self.headers)
            if not ok:
                self._send(code, b'{"error": "admin token required"}', ctype="application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length <= 0 or length > settings_ui.MAX_BODY_BYTES:
                    self._send(413 if length > settings_ui.MAX_BODY_BYTES else 400,
                               b'{"error": "bad request"}', ctype="application/json")
                    return
                payload = json.loads(self.rfile.read(length).decode())
            except Exception:
                self._send(400, b'{"error": "bad request"}', ctype="application/json")
                return
            key = payload.get("key") if isinstance(payload, dict) else None
            action = payload.get("action") if isinstance(payload, dict) else None
            ref_key = payload.get("ref_key") if isinstance(payload, dict) else None
            if not isinstance(key, str) or not isinstance(action, str):
                self._send(400, b'{"error": "key and action required"}', ctype="application/json")
                return
            if ref_key is not None and not isinstance(ref_key, str):
                self._send(400, b'{"error": "ref_key must be a string"}', ctype="application/json")
                return
            if action not in app.store._FEEDBACK_ACTIONS:
                self._send(400, b'{"error": "unknown action"}', ctype="application/json")
                return
            if action == "split" and not ref_key:
                # split is a PAIR action: it needs the subject it splits from.
                self._send(400, b'{"error": "split requires ref_key"}', ctype="application/json")
                return
            recorded = app.store.record_feedback(key, action, ref_key=ref_key)
            if not recorded:
                self._send(404, b'{"error": "unknown key (or duplicate)"}', ctype="application/json")
                return
            self._send(200, json.dumps({"applied": True, "action": action}).encode(),
                       ctype="application/json")

        def _do_provider_test(self, app, pid):
            # Admin-gated live probe of one provider (see module docstring).
            # Static "ping" payload -- no alert data, identifiers, or bundle
            # content ever leaves on this path, by construction (the payload
            # is a constant). Response carries latency + model echo only;
            # error bodies carry the exception TYPE only, never the message
            # (transport errors can echo the URL, which may embed basic-auth
            # credentials).
            ok, code = settings_ui.check_admin_token(app, self.headers)
            if not ok:
                self._send(code, b'{"error": "admin token required"}', ctype="application/json")
                return
            from nuncio import config as _config
            resolved = _config.resolve_provider_for_test(app.settings, unquote(pid or ""))
            if resolved is None:
                self._send(404, b'{"error": "unknown provider"}', ctype="application/json")
                return
            base_url, key, model, timeout_s, headers = resolved
            from nuncio.llm import LLMClient
            bound = min(timeout_s or 10.0, 15.0)
            client = LLMClient(base_url, key or "", model or "default", timeout=bound,
                               extra_headers=headers or {})
            start = time.monotonic()
            try:
                raw = client.enrich([{"role": "user", "content": "ping"}],
                                    max_tokens=8, timeout=bound)
            except Exception as e:
                self._send(502, json.dumps({"ok": False, "error": type(e).__name__}).encode(),
                           ctype="application/json")
                return
            content = raw[0] if isinstance(raw, tuple) and len(raw) == 2 else raw
            body = {
                "ok": True,
                "latency_ms": int((time.monotonic() - start) * 1000),
                "model": model or "default",
                "echo": (content or "")[:64],
            }
            self._send(200, json.dumps(body).encode(), ctype="application/json")

        def log_message(self, *a):
            pass  # quiet; nuncio emits its own structured metrics/logs

    return Handler


def serve(app, bind, port):
    server = ThreadingHTTPServer((bind, port), _handler_factory(app))
    print(f"nuncio listening on {bind}:{port}", flush=True)
    server.serve_forever()
