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
import json
import queue
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from nuncio import __version__, sources
from nuncio.clients import CollectorHealth
from nuncio.deadline import Deadline
from nuncio.fingerprint import fingerprint
from nuncio.model import categorize, real_host
from nuncio.redactor import redact
from nuncio.web import dashboard
from nuncio.web import settings as settings_ui

_RECEIVED = "received"
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

    def inc(self, attr, key=None):
        with self._lock:
            if key is None:
                setattr(self, attr, getattr(self, attr) + 1)
            else:
                d = getattr(self, attr)
                d[key] = d.get(key, 0) + 1

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
                 full_budget_s=60.0):
        self.engine = engine
        self.store = store
        self.metrics = metrics
        self.budget_s = budget_s
        self.full_budget_s = full_budget_s
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
        self.q = queue.Queue(maxsize=queue_max)
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
                self.q.put_nowait((pa.key, pa.alert, raw, deadline, mode, depth))
                self.metrics.queue_depth = self.q.qsize()
            except queue.Full:
                # load-shed: leave it persisted; the maintenance thread delivers
                # it raw at its deadline (does NOT block this handler).
                self.metrics.inc("failures", "queue")
        return status

    def _worker(self):
        while True:
            key, alert, raw, deadline, mode, depth = self.q.get()
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
                        outcome = self.engine.process(key, alert, raw, deadline=deadline, mode=mode, depth=depth)
                    else:
                        outcome = self.engine._deliver_raw(key, raw, fail_stage="deadline")
                else:
                    outcome = self.engine.process(key, alert, raw, deadline=deadline, mode=mode, depth=depth)
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
        its own deadline accounting)."""
        first_pass = True
        while True:
            try:
                if first_pass:
                    cutoff = self.wall_clock()
                    first_pass = False
                else:
                    cutoff = self.wall_clock() - (max(self.budget_s, self.full_budget_s) + self.maint_margin)
                for key, raw in self.store.undelivered_older_than(cutoff):
                    # Per-row isolation: undelivered_older_than() returns
                    # rows OLDEST-FIRST, so a single poisoned row that always
                    # raises must never abort the rest of the pass -- else
                    # that same row re-fails every cycle and permanently
                    # stalls recovery of every row after it. Mirrors
                    # Engine.drain_raw's try/except:continue.
                    try:
                        outcome = self.engine._deliver_raw(key, raw, fail_stage="queue")
                        if outcome == "raw":
                            self.metrics.inc("recovered")
                        elif outcome == "skipped_duplicate":
                            # BLOCKER 2b belt fired -- the worker already (or
                            # concurrently) delivered this key; not a
                            # failure, not a recovery, just a race avoided.
                            self.metrics.inc("duplicates_avoided")
                    except Exception:
                        self.metrics.inc("failures", "maintenance")
                        continue
                # Batch C: restart/orphan sweep for the assist plane's rich-
                # delivery leg -- a row stuck at assist_status='deferred'
                # past its own timeout (e.g. the process crashed with items
                # still on the assist worker's in-memory queue). A no-op
                # when the assist plane is disabled or has nothing pending.
                assist = getattr(self.engine, "assist", None)
                if assist is not None:
                    try:
                        assist.sweep_orphans()
                    except Exception:
                        self.metrics.inc("failures", "maintenance")
                self.store.purge_delivered(self.wall_clock() - self.retention_s)
            except Exception:
                self.metrics.inc("failures", "maintenance")
            time.sleep(self.maint_interval)


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
                self._send(200, app.metrics.render().encode())
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
            else:
                self._send(404, b"not found")

        def do_POST(self):
            if self.path == "/settings":
                self._do_post_settings()
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

        def log_message(self, *a):
            pass  # quiet; nuncio emits its own structured metrics/logs

    return Handler


def serve(app, bind, port):
    server = ThreadingHTTPServer((bind, port), _handler_factory(app))
    print(f"nuncio listening on {bind}:{port}", flush=True)
    server.serve_forever()
