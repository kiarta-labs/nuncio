"""Idempotency + persistence store.

SQLite single-file store. `synchronous=FULL` so a committed persist is fsync'd to
disk before we ACK CheckMK (persist-before-ACK). Duplicate keys are ignored
(at-least-once with best-effort dedup). `undelivered()` powers the restart-drain.

External-reader posture: a `busy_timeout` is set on the connection, so a
transient lock contention (e.g. an external process opening its own sqlite
session against the same file) degrades to a short wait rather than an
immediate "database is locked" error. That only covers reads -- an external
session must never WRITE to, or run `wal_checkpoint`/`vacuum` against,
`alerts.db` while nuncio is running; a read-only external session (e.g.
`sqlite3.connect(path, uri=True)` with `mode=ro`) is safe at any time.
"""
import sqlite3
import threading
import time

from nuncio.model import CANARY_PREFIX

_STATUS_RECEIVED = "received"


class Store:
    # Dashboard columns -- additive, all nullable.
    # `source`/`category`/`severity` are written once at persist() time (they
    # describe the ALERT, known at ingest, and must be recorded even for a
    # row that's later shed/never reaches the engine); the rest are written
    # by the engine via record_stats() as the alert moves through the
    # pipeline. Kept as one dict (name -> SQL type) so both the migration
    # loop and record_stats()'s whitelist derive from a single source of
    # truth -- a column can never be added to one without the other.
    _STATS_COLUMNS = {
        "source": "TEXT", "category": "TEXT", "severity": "TEXT",
        "fingerprint": "TEXT",      # recurrence signature (see nuncio.fingerprint) --
                                     # written at PERSIST time (like source/category/
                                     # severity), NOT via record_stats()
        "outcome": "TEXT",          # enriched|raw (see historical values in old audit rows)
        "fail_stage": "TEXT",       # queue|gather|redact|llm|validate|deadline|delivery|null
        "latency_ms": "INTEGER",    # ingest -> delivered wall time
        "llm_ms": "INTEGER",
        "tokens_in": "INTEGER", "tokens_out": "INTEGER",
        "redaction_count": "INTEGER", "bundle_bytes": "INTEGER",
        "enrichment": "TEXT",       # the delivered analysis text (audit; retention-purged)
        "assist_status": "TEXT",    # deferred|done|failed|skipped|null -- see nuncio.assist.AssistTrack
        "assist_insight": "TEXT",   # the assist plane's (already-redacted) insight text, if any
        "host": "TEXT",             # subject metadata -- persist-time, like source/category/severity
        "service": "TEXT",
        "enrich_format": "TEXT",    # structured|text|null -- see nuncio.engine's format ladder (Phase A)
    }
    # record_stats() may only ever touch the ones NOT already set at
    # persist() time (source/category/severity/fingerprint/host/service are
    # persist()'s job) -- keeps the two write paths from racing over the
    # same columns.
    _RECORD_STATS_FIELDS = tuple(
        c for c in _STATS_COLUMNS
        if c not in ("source", "category", "severity", "fingerprint", "host", "service")
    )

    def __init__(self, path, clock=time.time):
        # check_same_thread=False + a lock: the nuncio is concurrent (workers) but
        # typical deployment volume is low, so a single serialized connection is
        # simplest and safe. WAL keeps readers/writers from blocking each other.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._clock = clock  # wall clock for created_at (age-based recovery)
        # Set the busy-wait pragma before the WAL mode switch below -- a mode
        # change can itself hit BUSY, so the wait needs to already be in
        # effect for that first pragma call too.
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")  # durability before ACK
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts ("
            "  key TEXT PRIMARY KEY,"
            "  payload TEXT NOT NULL,"
            "  status TEXT NOT NULL,"
            "  seq INTEGER,"
            "  created_at REAL,"
            "  bundle TEXT,"         # redacted context bundle (audit trail)
            "  delivery_mode TEXT,"  # NUNCIO_MODE active when this alert was ingested
            "  raw_first_fired INTEGER DEFAULT 0"  # historical column -- see mark_delivered
            ")"
        )
        # index for created_at range scans (recent/undelivered_older_than/purge)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)")
        # Migration for DB files created before delivery_mode/raw_first_fired existed
        # (additive-only -- never touches existing columns/rows).
        existing_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "delivery_mode" not in existing_cols:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN delivery_mode TEXT")
        if "raw_first_fired" not in existing_cols:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN raw_first_fired INTEGER DEFAULT 0")
        # Dashboard columns -- all additive/nullable, PRAGMA-guarded exactly
        # like the migration above so a DB file created before these columns
        # existed still opens (and is unaffected by never re-running an
        # ALTER TABLE that already applied).
        for col, coltype in self._STATS_COLUMNS.items():
            if col not in existing_cols:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} {coltype}")
        # index for fingerprint_stats' recurrence lookups -- created AFTER the
        # migration loop above so the column it indexes is guaranteed to exist
        # (a fresh CREATE TABLE doesn't include it; only the loop adds it).
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(fingerprint)")
        # Historical-mode migration: a DB file from before the delivery-mode
        # collapse (see mark_delivered's docstring) may still have rows stuck
        # in the old interim 'delivered_raw_pending_enrich' status -- that
        # status no longer exists as a code path, so promote any leftover row
        # straight to the terminal 'delivered_raw' rather than leaving it
        # permanently unrecognized.
        self._conn.execute(
            "UPDATE alerts SET status = 'delivered_raw' WHERE status = 'delivered_raw_pending_enrich'"
        )
        self._conn.commit()

    def set_bundle(self, key, bundle):
        """Store the REDACTED context bundle for audit/replay. Never store a
        pre-redaction bundle."""
        with self._lock:
            self._conn.execute("UPDATE alerts SET bundle = ? WHERE key = ?", (bundle, key))
            self._conn.commit()

    def get_bundle(self, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT bundle FROM alerts WHERE key = ?", (key,)).fetchone()
        return row[0] if row and row[0] is not None else None

    def get_severity(self, key):
        """Best-effort severity lookup for a degraded raw-delivery path that
        has no `alert` dict handy (e.g. the maintenance/drain safety nets).
        Returns None if the key or a severity column isn't found -- the
        caller degrades to "unknown", never raises."""
        with self._lock:
            row = self._conn.execute(
                "SELECT severity FROM alerts WHERE key = ?", (key,)).fetchone()
        return row[0] if row and row[0] else None

    def get_created_at(self, key):
        """Wall-clock persist() time for `key`, or None if unknown -- used by
        the engine to compute ingest->delivered latency_ms."""
        with self._lock:
            row = self._conn.execute(
                "SELECT created_at FROM alerts WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def record_stats(self, key, **fields):
        """Best-effort partial update of the dashboard columns for one
        alert. Only the whitelisted
        `_RECORD_STATS_FIELDS` may be written (a typo'd/unknown field name
        raises immediately -- a programming error, not a runtime one, so it
        is NOT swallowed here; the ENGINE is responsible for wrapping this
        call so a failure here can never break delivery -- see
        `Engine._record_stats`). A no-op (no query at all) when no fields
        are given."""
        unknown = set(fields) - set(self._RECORD_STATS_FIELDS)
        if unknown:
            raise ValueError(f"record_stats: unknown field(s) {sorted(unknown)}")
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [key]
        with self._lock:
            self._conn.execute(f"UPDATE alerts SET {set_clause} WHERE key = ?", values)
            self._conn.commit()

    # --- dashboard read paths -- all pure reads, no mutation, safe to call
    # from GET handlers concurrently with ingest. ---

    _ROW_COLS = (
        "key", "payload", "status", "created_at", "source", "category",
        "severity", "fingerprint", "outcome", "fail_stage", "latency_ms", "llm_ms",
        "tokens_in", "tokens_out", "redaction_count", "bundle_bytes",
        "delivery_mode", "raw_first_fired", "assist_status", "host", "service",
        "enrich_format",
    )

    def status_counts(self):
        """{status: count} across ALL rows (all-time, restart-surviving) --
        backs /stats.json `totals`."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall()
        return {s: n for s, n in rows}

    def count_all(self):
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return row[0] if row else 0

    def rows_since(self, since):
        """Every column the dashboard needs, for rows created_at >= `since`,
        as plain dicts -- feeds /stats.json's windowed aggregates. Typical
        alert volume (<10^3/day) makes pulling the window into Python and
        aggregating there (rather than SQL window functions -- sqlite has no
        native percentile) the simpler, more portable choice."""
        cols = ", ".join(self._ROW_COLS)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT {cols} FROM alerts WHERE created_at >= ? ORDER BY created_at",
                (since,),
            ).fetchall()
        return [dict(zip(self._ROW_COLS, r)) for r in rows]

    def recent_rows(self, limit=50, source=None, outcome=None):
        """Newest-first rows for GET /alerts.json, with optional
        source/outcome filters. Excludes synthetic canaries (same
        convention as recent()). Includes `payload` (the raw text) but NOT
        `bundle`/`enrichment` (those are the drill-down's job, get_alert_detail
        below) -- `payload` is already REDACTED at ingest (server.py redacts
        before persist()), so exposing it here can never leak a secret (rule 1)."""
        cols = ", ".join(self._ROW_COLS)
        query = f"SELECT {cols} FROM alerts WHERE key NOT LIKE ?"
        params = [CANARY_PREFIX + "%"]
        if source:
            query += " AND source = ?"
            params.append(source)
        if outcome:
            query += " AND outcome = ?"
            params.append(outcome)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(zip(self._ROW_COLS, r)) for r in rows]

    def get_alert_detail(self, key):
        """Full row (incl. bundle + enrichment text) for GET /alert/<key> --
        the transparency drill-down. Both `bundle` and `enrichment` are only
        ever written from already-REDACTED text (set_bundle()'s docstring/
        callers; engine only records the post-redaction enrichment string --
        rule 1), so this is safe to render verbatim."""
        cols = self._ROW_COLS + ("bundle", "enrichment", "assist_insight")
        col_sql = ", ".join(cols)
        with self._lock:
            row = self._conn.execute(
                f"SELECT {col_sql} FROM alerts WHERE key = ?", (key,)).fetchone()
        return dict(zip(cols, row)) if row else None

    def persist(self, key, payload, mode=None, source=None, category=None, severity=None,
                fingerprint=None, host=None, service=None):
        """Persist a new alert. Returns True if newly stored, False if the key
        already exists (duplicate — original is left untouched). `mode` is
        the NUNCIO_MODE active at ingest time, recorded for dashboard/audit
        use -- optional, defaults to None for callers that don't track it.
        `source`/`category`/`severity`/`fingerprint`/`host`/`service` are the
        alert's own metadata, known at ingest time -- recorded here (not via
        record_stats()) so even a load-shed row that the engine never sees
        still shows up correctly on the dashboard's by-source/by-category/
        by-severity/by-subject breakdowns (and is findable by
        `fingerprint_stats`). All optional, default None."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO alerts "
                "(key, payload, status, seq, created_at, delivery_mode, source, category, severity, "
                " fingerprint, host, service) "
                "VALUES (?, ?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM alerts), ?, ?, ?, ?, ?, ?, ?, ?)",
                (key, payload, _STATUS_RECEIVED, self._clock(), mode, source, category, severity,
                 fingerprint, host, service),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def fingerprint_stats(self, fp, window_s, now=None):
        """(count, first_seen) for alerts sharing fingerprint `fp` within the
        backward window `[now-window_s, now]`, excluding synthetic canaries.
        `count` includes the current alert if it's already persisted (so the
        SECOND occurrence of a signature reads count=2). `first_seen` is the
        earliest `created_at` in that window, or None if `count` is 0.
        `now` defaults to wall-clock time."""
        now = self._clock() if now is None else now
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*), MIN(created_at) FROM alerts "
                "WHERE fingerprint = ? AND created_at >= ? AND key NOT LIKE ?",
                (fp, now - window_s, CANARY_PREFIX + "%"),
            ).fetchone()
        count = row[0] if row else 0
        first_seen = row[1] if row and row[1] is not None else None
        return count, first_seen

    def claim_assist(self, key):
        """Atomic CAS claim of `key` for the assist worker, moving
        `assist_status` to `'in_flight'` -- but ONLY if it is still
        `'deferred'` or unset (`NULL`). Returns True iff THIS call performed
        the transition; False means some other path (the orphan sweep, a
        duplicate/late worker item) already moved the row past that point
        (`'in_flight'`/`'failed'`/`'done'`/`'skipped'`), so the caller must
        not send the rich leg again.

        The `NULL` arm exists because the submit-time
        `record_stats(key, assist_status="deferred")` write in
        `Engine._deliver_enriched` is best-effort and can fail (status stays
        `NULL`) without losing the alert -- this lets the worker still claim
        and deliver that row instead of silently dropping the rich leg (see
        `nuncio.assist.AssistTrack._process_item`).

        Single UPDATE with a WHERE guard, executed under `self._lock`
        alongside every other store call, so this is race-free against any
        concurrent caller (worker thread vs. the maintenance-thread sweep)."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET assist_status = 'in_flight' "
                "WHERE key = ? AND (assist_status = 'deferred' OR assist_status IS NULL)",
                (key,),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def claim_assist_for_sweep(self, key):
        """Atomic CAS claim of `key` for the restart/orphan sweep, moving
        `assist_status` from `'deferred'` straight to the terminal
        `'failed'` (mark-before-send, so a crash before the send below can
        never re-sweep this row -- see
        `nuncio.assist.AssistTrack.sweep_orphans`'s docstring). Returns True
        iff THIS call performed the transition; False means the row is no
        longer `'deferred'` (e.g. a worker already claimed it via
        `claim_assist` above), in which case the sweep must NOT deliver a
        second rich leg for it.

        Deliberately does NOT accept the `NULL` arm `claim_assist` does --
        the sweep only ever operates on rows its own
        `deferred_assist_older_than` query already selected as
        `'deferred'`; a `NULL` row was never deferred in the first place and
        is the worker's problem, not the sweep's."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET assist_status = 'failed' "
                "WHERE key = ? AND assist_status = 'deferred'",
                (key,),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def get_assist_status(self, key):
        """Best-effort current `assist_status` for `key`, or None if the key
        or the field is unset -- used by the assist worker's race guard
        against the restart/orphan sweep (see nuncio.assist.AssistTrack)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT assist_status FROM alerts WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def deferred_assist_older_than(self, cutoff):
        """(key, payload, severity, enrichment) for rows still stuck at
        `assist_status = 'deferred'` and created before `cutoff` (epoch) --
        the restart/orphan safety net for the assist plane's rich-delivery
        leg (see nuncio.assist.AssistTrack.sweep_orphans)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, payload, severity, enrichment FROM alerts "
                "WHERE assist_status = 'deferred' AND created_at < ? ORDER BY seq",
                (cutoff,),
            ).fetchall()
        return [tuple(r) for r in rows]

    def undelivered_older_than(self, cutoff):
        """(key, payload) for undelivered rows created before `cutoff` (epoch),
        oldest first — the age-based safety net for stuck/queued-past-deadline
        alerts."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, payload FROM alerts "
                "WHERE status = ? AND created_at < ? ORDER BY seq",
                (_STATUS_RECEIVED, cutoff),
            ).fetchall()
        return [(k, p) for k, p in rows]

    # Terminal statuses this store knows about:
    #   delivered_enriched - single-message enriched success
    #   delivered_raw      - raw-only, terminal (enriched-mode fallback, or a
    #                         plain bypass delivery)
    # `delivery_mode`/`raw_first_fired` remain as columns (with their
    # ALTER TABLE migrations) purely for historical/audit continuity with
    # rows written before the delivery-mode collapse; nothing in this build
    # writes to `raw_first_fired` anymore.
    _MARK_MODES = ("enriched", "raw")

    def mark_delivered(self, key, mode):
        """mode in _MARK_MODES -> status delivered_<mode>."""
        if mode not in self._MARK_MODES:
            raise ValueError(f"invalid delivery mode: {mode!r}")
        status = f"delivered_{mode}"
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET status = ? WHERE key = ?",
                (status, key),
            )
            self._conn.commit()

    def get_status(self, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM alerts WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def get_delivery_mode(self, key):
        """The NUNCIO_MODE recorded at persist() time for this alert."""
        with self._lock:
            row = self._conn.execute(
                "SELECT delivery_mode FROM alerts WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def get_payload(self, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM alerts WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def undelivered(self):
        """(key, payload) for every alert not yet delivered, oldest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, payload FROM alerts WHERE status = ? ORDER BY seq",
                (_STATUS_RECEIVED,),
            ).fetchall()
        return [(k, p) for k, p in rows]

    def recent(self, before, window_s, exclude_key=None, limit=20):
        """(key, payload, created_at, source, category, severity, fingerprint,
        host, service) for alerts received in [before-window_s, before),
        excluding `exclude_key`, newest-first-capped to `limit`, returned
        oldest-first. Backward-only — at enrichment time the future hasn't
        happened. `host`/`service` are the persist()-time subject metadata
        (see nuncio/server.py's persist call site) -- `nuncio.correlate`'s
        gate matches on these columns directly rather than regexing the
        rendered summary text."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT key, payload, created_at, source, category, severity, fingerprint, "
                "host, service FROM alerts "
                "WHERE created_at >= ? AND created_at < ? AND key IS NOT ? "
                "AND key NOT LIKE ? "  # synthetic canaries never pollute correlation
                "ORDER BY created_at DESC LIMIT ?",
                (before - window_s, before, exclude_key, CANARY_PREFIX + "%", limit),
            ).fetchall()
        return list(reversed([tuple(r) for r in rows]))

    def purge_delivered(self, cutoff):
        """Delete delivered rows created before `cutoff` (epoch). Keeps the store
        (and the seq MAX subquery) bounded. Returns rows removed."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM alerts WHERE status LIKE 'delivered_%' AND created_at < ?",
                (cutoff,),
            )
            self._conn.commit()
            return cur.rowcount

    def close(self):
        with self._lock:
            self._conn.close()
