"""Out-of-band "assist" plane — a single, optional hosted-LLM call per
eligible alert, made STRICTLY AFTER the primary alert has already been
delivered.

This is NOT an agentic loop and it NEVER runs inside the 30s alert deadline
(`nuncio.deadline.Deadline`/`Engine.budget_s`). The primary push already went
out fast, on the engine's normal fail-safe path; this module enriches the
rich/full-verbosity delivery leg only, at most `NUNCIO_ASSIST_TIMEOUT_S`
(default 60s) later, on its own dedicated worker thread with its own
dedicated budget. Assist failure or timeout must NEVER affect the primary
alert — by construction, it cannot: the primary send has already completed
by the time anything here runs.

`AssistClient` is a thin, structurally-gated wrapper around one `LLMClient`
call: `insight()` only accepts a `redactor.ScrubbedPayload` (see
`nuncio.redactor.scrub_for_assist_plane`), enforced by an `isinstance` check
that raises `TypeError` otherwise — so there is no code path in this module
that can hand raw/unscrubbed alert text to the underlying LLM call.

`AssistTrack` owns the queue + worker thread + the deferred-delivery and
restart/orphan-sweep bookkeeping. See `Engine.process`'s deferral logic for
how an alert gets here in the first place.
"""
import logging
import queue
import threading
import time
from dataclasses import replace as _dc_replace
from html import escape as _html_escape

from nuncio.deadline import Deadline, run_bounded
from nuncio.redactor import ScrubbedPayload, redact, scrub_for_assist_plane

log = logging.getLogger("nuncio.assist")

_ASSIST_SYSTEM = (
    "You are given a scrubbed infrastructure incident description. "
    "Placeholders like <ip-1>, <user-1>, <email-1> replace real identifiers; "
    "treat them as stable labels. In AT MOST 3 short sentences, state the "
    "single most likely root cause and the one most useful fix or check. If "
    "genuinely unclear, say what evidence is missing in one sentence. No "
    "headings, no preamble."
)

_ASSIST_BLOCK_LABEL = "--- External assist (scrubbed):"


def _assist_messages(text):
    return [
        {"role": "system", "content": _ASSIST_SYSTEM},
        {"role": "user", "content": text},
    ]


class AssistClient:
    """Wraps exactly one underlying `LLMClient`. Nothing else in this
    process holds that client directly — `nuncio.config.build_assist`
    constructs it inline and hands it straight here."""

    def __init__(self, llm_client):
        self._llm = llm_client

    def insight(self, payload):
        if not isinstance(payload, ScrubbedPayload):
            raise TypeError(
                "AssistClient.insight() requires a redactor.ScrubbedPayload "
                "-- construct one via nuncio.redactor.scrub_for_assist_plane(); "
                f"got {type(payload).__name__!r}"
            )
        raw = self._llm.enrich(_assist_messages(payload.text), max_tokens=200)
        if isinstance(raw, tuple) and len(raw) == 2:
            content, _usage = raw
        else:
            content = raw
        return content


class AssistTrack:
    """The queue + worker + deferred-delivery/orphan-sweep machinery for the
    assist plane. Constructed only when the plane is enabled
    (`nuncio.config.build_assist` returns None otherwise) — `Engine.assist`
    being `None` is itself the "disabled" signal everywhere else in the
    pipeline.
    """

    def __init__(self, client, dispatch, store, metrics=None, timeout_s=60.0,
                 severities=("critical",), posture="generic", queue_max=8,
                 classification_table=None, clock=time.monotonic, wall_clock=time.time):
        self.client = client
        self.dispatch = dispatch
        self.store = store
        self.metrics = metrics
        self.timeout_s = timeout_s
        self.severities = set(severities)
        self.posture = posture
        self.classification_table = dict(classification_table or {})
        self._clock = clock
        self._wall_clock = wall_clock
        self._q = queue.Queue(maxsize=queue_max)
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def eligible(self, severity, mode):
        """Whether an alert of this severity, ingested under this delivery
        mode, may be deferred to the assist plane. `bypass` mode is excluded
        by construction: `mode` must be exactly `"enriched"` (bypass alerts
        never even reach the enrichment path that would call this)."""
        return mode == "enriched" and severity in self.severities

    def submit(self, key, envelope, context_text, followup=False):
        """Non-blocking enqueue. Returns True if accepted, False if the
        queue is full (the caller — `Engine.process` — treats False as "the
        assist plane is saturated; delivery the rich copy right now with no
        insight instead of waiting")."""
        try:
            self._q.put_nowait((key, envelope, context_text, followup))
            return True
        except queue.Full:
            return False

    # --- worker ---

    def _worker(self):
        while True:
            item = self._q.get()
            try:
                self._process_item(*item)
            except Exception:
                log.warning("assist worker: unhandled error processing item", exc_info=True)
            finally:
                self._q.task_done()

    def _process_item(self, key, envelope, context_text, followup):
        if self.metrics is not None:
            try:
                self.metrics.inc("assist_attempted")
            except Exception:
                pass

        if not followup:
            # Atomic claim against the restart/orphan sweep (see
            # Store.claim_assist): moves assist_status 'deferred'/NULL ->
            # 'in_flight'. NULL is claimable too -- the submit-time
            # `assist_status="deferred"` write in Engine is best-effort and
            # can fail without losing the alert; treating a still-NULL row
            # as claimable (rather than "already handled") means a transient
            # store hiccup at submit time degrades to "deliver the rich leg
            # late" rather than "silently drop it". False means some other
            # path (the sweep, a duplicate/late item) already claimed this
            # key -- skip, at-most-once for the rich leg. On a store error
            # here, proceed rather than risk silently dropping the leg (the
            # same fail-open posture the old race guard used).
            try:
                if not self.store.claim_assist(key):
                    return
            except Exception:
                pass

        payload = scrub_for_assist_plane(context_text or "")
        deadline = Deadline(self.timeout_s, clock=self._clock)
        try:
            raw_insight = run_bounded(lambda: self.client.insight(payload), deadline.remaining())
        except Exception as e:
            self._on_failure(key, envelope, followup, e)
            return
        insight = redact(raw_insight or "")[0].strip()
        if not insight:
            self._on_failure(key, envelope, followup, ValueError("empty assist response"))
            return
        self._on_success(key, envelope, followup, insight)

    def _on_success(self, key, envelope, followup, insight):
        if self.metrics is not None:
            try:
                self.metrics.inc("assist_ok")
            except Exception:
                pass
        try:
            self.store.record_stats(key, assist_status="done", assist_insight=insight)
        except Exception:
            pass
        out_envelope = _followup_envelope(envelope, insight) if followup else _merge_insight(envelope, insight)
        try:
            self.dispatch.send_full(out_envelope)
        except Exception:
            log.warning("assist: send_full raised after a successful insight", exc_info=True)

    def _on_failure(self, key, envelope, followup, exc):
        if self.metrics is not None:
            try:
                self.metrics.inc("assist_failed")
            except Exception:
                pass
        log.warning("assist plane failed/timed out for %s: %r", key, exc)
        try:
            self.store.record_stats(key, assist_status="failed")
        except Exception:
            pass
        if followup:
            # The primary alert already went out in full on the normal path
            # (there was no brief leg to defer past) -- on assist failure
            # there is nothing new to say, and re-sending the original would
            # be a pure duplicate. Silently drop.
            return
        # The deferred path: only the BRIEF leg has gone out so far. The rich
        # leg must still go, just late and without an insight.
        try:
            self.dispatch.send_full(envelope)
        except Exception:
            log.warning("assist: send_full raised on the no-insight fallback", exc_info=True)

    # --- restart/orphan sweep (called from the maintenance thread) ---

    def sweep_orphans(self):
        """Safety net for a crash/restart that leaves a row stuck at
        `assist_status='deferred'` forever (its worker item was lost with
        the in-memory queue). Delivers the rich leg with NO insight (same
        shape as a normal assist failure) for any such row older than
        `timeout_s + 30`s.

        AT-MOST-ONCE for the rich leg, by construction: `assist_status` is
        claimed (CAS 'deferred' -> 'failed', see `Store.claim_assist_for_sweep`)
        BEFORE the send below, not after. If the process crashes between the
        two, the row is already `'failed'` and will never be swept again on
        the next restart -- the rich copy is lost, never duplicated. (The
        alert itself is not at risk either way: the brief leg already went
        out on the normal fail-safe path before this row could ever reach
        `'deferred'`.)

        The CAS also guards against the WORKER: under a critical-alert
        backlog a `'deferred'` row can outlive `timeout_s + 30` while its
        item is still queued/mid-call on the worker thread. If the worker
        wins the race (claims via `Store.claim_assist` first), this row is
        no longer `'deferred'` by the time the claim below runs, the claim
        returns False, and the sweep skips it -- exactly one of
        {worker, sweep, queue-full-immediate} ever sends the rich leg for a
        given key.
        """
        cutoff = self._wall_clock() - (self.timeout_s + 30)
        for key, payload, severity, enrichment in self.store.deferred_assist_older_than(cutoff):
            try:
                if not self.store.claim_assist_for_sweep(key):
                    continue  # a worker (or a previous sweep pass) already claimed it
                envelope = _reconstruct_envelope(payload, severity, enrichment)
                self.dispatch.send_full(envelope)
            except Exception:
                log.warning("assist orphan sweep: failed to recover %s", key, exc_info=True)
                continue


def _merge_insight(envelope, insight):
    """Append the insight to the SAME envelope that was (or will be)
    delivered in full -- used for the deferred path, where the brief leg
    already carried the primary content and this is the rich follow-through,
    not a second alert."""
    detail = (envelope.detail or "").rstrip() + f"\n\n{_ASSIST_BLOCK_LABEL}\n{insight}\n"
    detail_html = envelope.detail_html
    if detail_html:
        detail_html = detail_html + f"<h4>External assist (scrubbed)</h4><pre>{_html_escape(insight)}</pre>"
    return _dc_replace(envelope, detail=detail, detail_html=detail_html)


def _followup_envelope(envelope, insight):
    """A NEW, separate envelope for the "primary already went out in full"
    case (e.g. NUNCIO_DELIVERY=email alone -- no brief leg exists to defer
    past). Titled distinctly so it reads as a follow-up, not a duplicate of
    the alert that already arrived."""
    headline = f"Assist follow-up: {envelope.headline}"
    detail = f"{_ASSIST_BLOCK_LABEL}\n{insight}\n"
    detail_html = f"<h4>External assist (scrubbed)</h4><pre>{_html_escape(insight)}</pre>"
    return _dc_replace(envelope, headline=headline, summary=insight[:200], detail=detail, detail_html=detail_html)


def _reconstruct_envelope(payload, severity, enrichment):
    """Best-effort envelope for the orphan sweep, which has only what the
    store kept (the already-redacted raw payload + the already-redacted
    enrichment text) -- no live `alert`/`Envelope` object survives a
    restart. Never carries an insight (the sweep never calls the LLM)."""
    from nuncio.envelope import Envelope, build_headline, severity_to_notify_type

    severity = severity or "unknown"
    enrichment = (enrichment or "").strip()
    payload = payload or ""
    summary = next((ln.strip() for ln in enrichment.splitlines() if ln.strip()), "") \
        or next((ln.strip() for ln in payload.splitlines() if ln.strip()), "")
    headline = build_headline(severity, "", "", summary)
    detail = (enrichment or payload or "(no detail available)") + f"\n\n{_ASSIST_BLOCK_LABEL}\n(unavailable -- recovered after a restart)\n"
    return Envelope(
        severity=severity, host="", service="", headline=headline, summary=summary,
        detail=detail, detail_html=None, notify_type=severity_to_notify_type(severity), marker=False,
    )
