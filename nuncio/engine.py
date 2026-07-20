"""Fail-safe enrichment engine — Level A.

Invariant: for every alert, exactly one message is delivered. In `enriched`
mode (the default) that's the enriched result on the happy path, or the raw
alert + `[enrichment unavailable]` marker on ANY failure/timeout, and the
store is marked (`delivered_enriched` | `delivered_raw`). `bypass` mode skips
enrichment entirely and delivers the plain raw alert (no marker — this is an
intentional pass-through, not a degraded fallback). If the channel itself is
down, nothing is marked and the record stays for the restart-drain.

The engine holds ONLY a single LLM client, kept structurally separate from any
future higher-privilege or higher-cost model tier so a low-trust alert path can
never accidentally reach it.

All collaborators (store, llm, delivery) and the pure functions (redact,
build-messages, validate) are injected, so the whole fail-safe surface is
testable offline with a fake clock.

Best-effort dashboard-stats capture (`_record_stats`) is layered on top. It is
a HARD rule that a stats-write failure can never lose or delay an alert: every
`_record_stats` call happens strictly AFTER the delivery-defining action (a
successful `delivery.send()` + `store.mark_delivered()`) has already
completed, and the call itself is wrapped so nothing it does can raise back
into the fail-safe control flow (see `_record_stats`'s docstring).
"""
import json
import logging
import re
import time
from dataclasses import replace as _dc_replace

from nuncio.bundle import assemble_bundle
from nuncio.deadline import Deadline, run_bounded
from nuncio.envelope import Envelope, build_detail_html, build_headline, severity_to_notify_type
from nuncio.fingerprint import fingerprint as compute_fingerprint
from nuncio.llm import LLMError
from nuncio.model import categorize, disposition
from nuncio.redactor import redact, scrub_for_knowledge_plane
from nuncio.prompt import (
    build_level_a_messages, build_level_b_messages, build_knowledge_messages, validate_output,
    normalize_enrichment, render_structured, validate_structured, build_full_triage_messages,
)
from nuncio.render import build_envelope, RAW_FALLBACK_MARKER

log = logging.getLogger("nuncio.engine")

KNOWLEDGE_GUIDANCE_HEADER = "General guidance (knowledge plane)"

# Mirrors the delivery-adapter ring's BRIEF/FULL string values WITHOUT
# importing that ring module -- the core (this file) must never import an
# adapter ring (see tests/test_sources_registry.py's
# test_core_modules_never_import_adapter_rings); `Dispatch.has_verbosity()`
# is called duck-typed (via getattr, see `_delivery_has_verbosity` below) so
# the core stays decoupled from the ring even though it now reasons about
# verbosity for the assist-deferral decision.
_BRIEF, _FULL = "brief", "full"

# NUNCIO_MODE. Validated in nuncio/config.py at startup; re-checked here
# (cheaply) so a hand-built Engine (tests, scripts) can't silently no-op into
# unbranched behavior on a typo'd mode string.
VALID_MODES = ("enriched", "bypass")

# NUNCIO_ENRICH_FORMAT. "auto" tries the structured-JSON contract first (with
# per-endpoint capability detection, see Engine._enrich); "text" is the
# escape hatch that never sends response_format at all. Deliberately no
# strict "json" mode -- that would violate the never-lose invariant on an
# endpoint that can't honor it. Validated in nuncio/config.py at startup;
# re-checked here for the same hand-built-Engine reason as VALID_MODES.
VALID_ENRICH_FORMATS = ("auto", "text")

# NUNCIO_ENRICH_DEPTH (Phase B). "full" (the default) runs the richer,
# store-only-history-plus-bounded-2-call pipeline (see Engine._enrich_full);
# "low" is the Phase-A single-call path unchanged. Validated in
# nuncio/config.py at startup; re-checked here for the same hand-built-Engine
# reason as VALID_MODES/VALID_ENRICH_FORMATS.
VALID_DEPTHS = ("full", "low")

# Phase B ladder constants -- see Engine._enrich_full's docstring for the
# full worked budget walkthrough (10 gather + 15 triage + 30 RCA + 3 delivery
# reserve = 58s <= the 60s default NUNCIO_FULL_BUDGET_S).
_FULL_POST_GATHER_RESERVE_S = 48.0   # gather gate: skip the 2-call flow below this much remaining
_FULL_GATHER_BOUND_S = 10.0          # network-collector gather budget cap
_FULL_TRIAGE_MIN_REMAINING_S = 38.0  # below this, skip the triage call entirely
_FULL_TRIAGE_BOUND_S = 15.0          # triage call's own bound cap
_FULL_TRIAGE_RESERVE_S = 35.0        # reserved for call 2 + delivery when sizing the triage bound
_FULL_RCA_BOUND_S = 30.0             # deep RCA call's bound cap
_FULL_RCA_DELIVERY_RESERVE_S = 3.0   # reserved for delivery after the RCA call
_FULL_RCA_TIGHT_MIN_S = 8.0          # below this bound, RCA degrades to a single tight-bound attempt
_FULL_MAX_BUNDLE_BYTES = 64000       # hard cap on the deep bundle, regardless of NUNCIO_BUNDLE_MAX_BYTES

# The four canonical severities a structured response's "severity" key (see
# nuncio.prompt._SEVERITY_INFER_ADDENDUM_JSON) may declare -- anything else is
# "the model didn't comply", same posture as parse_inferred_severity's text
# equivalent.
_CANONICAL_SEVERITIES = ("critical", "warning", "info", "ok")


# Matches the leading "SEVERITY=<value>" line nuncio.prompt's
# _SEVERITY_INFER_ADDENDUM asks the model for when the source's own severity
# is unknown -- see parse_inferred_severity below. Tolerant of surrounding
# whitespace and a case-insensitive value; the KEY must be spelled
# "SEVERITY" (case-insensitive too, since a model won't always honor
# "uppercase key" literally) and the value must be one of the 4 canonical
# severities -- anything else is treated as "the model didn't comply" rather
# than guessed at.
_INFERRED_SEVERITY_RE = re.compile(
    r"^[ \t]*SEVERITY[ \t]*=[ \t]*(critical|warning|info|ok)[ \t]*\r?\n(?:[ \t]*\r?\n)?",
    re.IGNORECASE,
)


def parse_inferred_severity(text):
    """Parse and strip a leading "SEVERITY=<value>" line from an enrichment
    response. Returns `(severity_or_None, cleaned_text)`:
      - a match strips that line (and one following blank line, if present)
        and returns the lowercased severity value + the remaining text;
      - no match (line absent, malformed, or not one of the 4 allowed
        values) returns `(None, text unchanged)` -- fail-safe, never raises,
        never guesses.
    Pure and side-effect-free so it's directly unit-testable; see
    Engine.process for how the parsed value is used (and never applied over
    an already-known, source-derived severity)."""
    if not text:
        return None, text or ""
    m = _INFERRED_SEVERITY_RE.match(text)
    if not m:
        return None, text
    return m.group(1).lower(), text[m.end():]


def _sum_usage(a, b):
    """Merge two `{"prompt_tokens", "completion_tokens"}` usage dicts
    (either may be None) by summing each key, None-safe -- Phase B's 2-call
    pipeline sums the triage + RCA calls' token usage into the single
    dashboard stat every other call already populates. Returns None only
    when BOTH inputs are None/falsy (matches the pre-Phase-B single-call
    convention of "no usage reported")."""
    if not a and not b:
        return None
    out = {}
    for key in ("prompt_tokens", "completion_tokens"):
        va = (a or {}).get(key)
        vb = (b or {}).get(key)
        out[key] = None if va is None and vb is None else (va or 0) + (vb or 0)
    return out


class _Fallback(Exception):
    """Internal signal to drop to the raw-delivery path."""


class Engine:
    def __init__(self, store, llm, delivery,
                 redact_fn=redact, build_messages_fn=build_level_a_messages,
                 build_messages_b_fn=build_level_b_messages,
                 validate_fn=validate_output, gatherer=None,
                 budget_s=30.0, per_attempt_s=10.0, delivery_budget_s=3.0,
                 gather_reserve_s=8.0, mode="enriched",
                 clock=time.monotonic, wall_clock=time.time,
                 router=None, knowledge_llm=None,
                 fingerprint_window_s=172800, evidence_max_bytes=32000,
                 assist=None, enrich_format="auto",
                 depth="full", full_budget_s=60.0):
        if mode not in VALID_MODES:
            raise ValueError(f"invalid NUNCIO_MODE: {mode!r}; must be one of {VALID_MODES}")
        if enrich_format not in VALID_ENRICH_FORMATS:
            raise ValueError(
                f"invalid NUNCIO_ENRICH_FORMAT: {enrich_format!r}; must be one of {VALID_ENRICH_FORMATS}"
            )
        if depth not in VALID_DEPTHS:
            raise ValueError(f"invalid NUNCIO_ENRICH_DEPTH: {depth!r}; must be one of {VALID_DEPTHS}")
        self.store = store
        self.llm = llm
        self.delivery = delivery
        self._redact = redact_fn
        self._build_messages = build_messages_fn
        self._build_messages_b = build_messages_b_fn
        self._validate = validate_fn
        self.gatherer = gatherer  # set -> Level B (context gathering); None -> Level A
        self.budget_s = budget_s
        self.per_attempt_s = per_attempt_s
        self.delivery_budget_s = delivery_budget_s
        self.gather_reserve_s = gather_reserve_s
        self.mode = mode
        self._clock = clock
        self._wall_clock = wall_clock
        # Knowledge plane (opt-in, OFF unless both are set): `router` gates which
        # alert classes may reach it (allowlist by construction -- see
        # nuncio.router.Router), `knowledge_llm` is the second LLMClient it's
        # actually called against. Either being None disables the plane
        # entirely -- see `_garnish_with_knowledge`.
        self.router = router
        self.knowledge_llm = knowledge_llm
        # Batch B: recurrence headline suffix window (see nuncio.fingerprint)
        # and the HTML/plain-text evidence-section cap (see build_envelope's
        # sections_red / nuncio.envelope.build_detail_html).
        self.fingerprint_window_s = fingerprint_window_s
        self.evidence_max_bytes = evidence_max_bytes
        # Batch C: optional out-of-band assist plane (nuncio.assist.AssistTrack).
        # None (the default) means disabled -- `process()`'s deferral logic
        # checks this directly, so a disabled assist plane behaves EXACTLY
        # like the pre-Batch-C engine (no regression).
        self.assist = assist
        # NUNCIO_ENRICH_FORMAT (Phase A). "auto" attempts the structured-JSON
        # contract, with per-LLMClient capability detection (see
        # `self.llm._json_object_supported`, read/written by `_enrich`);
        # "text" never attempts it. See VALID_ENRICH_FORMATS above.
        self.enrich_format = enrich_format
        # Phase B: NUNCIO_ENRICH_DEPTH ("full" default, "low" opt-out) +
        # NUNCIO_FULL_BUDGET_S (informational here -- the actual budget a
        # full-depth alert runs under is baked into the `Deadline` object
        # server.py builds at ingest time, see nuncio.server.App.ingest; this
        # attribute exists so the settings screen / apply_changes has
        # somewhere to write a live change, see nuncio.config.apply_changes).
        self.depth = depth
        self.full_budget_s = full_budget_s

    def process(self, key, alert, raw_text, deadline=None, mode=None, depth=None):
        """Enrich + deliver one already-persisted alert. Returns
        'enriched' | 'raw' | 'delivery_failed'.

        `mode` is the delivery-safety mode this SPECIFIC alert was ingested
        under (threaded through the queue tuple by server.py); it defaults
        to the engine's current `self.mode` for every caller that doesn't
        track it (nearly all existing tests). Using the ingest-time mode
        rather than always re-reading `self.mode` means a live settings
        change to NUNCIO_MODE mid-flight can never re-route an alert that's
        already committed to a code path -- each alert lives its whole life
        under the mode it was ingested with; the toggle affects only new
        alerts.

        `bypass` mode delivers the raw alert as-is, no enrichment attempted,
        no marker -- checked BEFORE the deadline check since a bypass alert
        has nothing to time out on. It still rides this same
        persist->queue->worker->_deliver_raw machinery (rather than being
        shipped straight from the ingest thread) so the never-lose invariant
        stays exactly as hardened for every mode. `enriched` mode is the
        original single-message flow: wait for enrichment, fall back to raw
        + RAW_FALLBACK_MARKER on ANY failure/timeout.

        `depth` (Phase B) mirrors `mode`'s threading discipline exactly: the
        ingest-time depth for THIS alert (threaded through the queue tuple by
        server.py, which also builds `deadline` from the matching full/std
        budget for that depth -- see nuncio.server.App.ingest), defaulting to
        the engine's current `self.depth` for callers that don't track it.
        A live NUNCIO_ENRICH_DEPTH settings-screen flip can therefore never
        re-route an alert that's already committed to a code path (and,
        critically, never orphan a `deadline` built for one budget onto the
        other depth's pipeline)."""
        if deadline is None:
            deadline = Deadline(self.budget_s, clock=self._clock)
        effective_mode = mode if mode is not None else self.mode
        effective_depth = depth if depth is not None else self.depth
        if effective_mode == "bypass":
            return self._deliver_raw(key, raw_text, marker=False, alert=alert)
        try:
            if deadline.expired():
                raise _Fallback("deadline before start")
            min_lines = 2 if self.gatherer is not None else 1
            if effective_depth == "full" and self.gatherer is not None:
                enrichment, usage, meta = self._enrich_full(alert, deadline, key)
            else:
                enrichment, usage, meta = self._enrich(alert, deadline, key)
            structured = meta.get("enrich_format") == "structured"
            # Severity inference (LLM-classified) ONLY when the source
            # couldn't determine it -- a known, source-derived severity is
            # authoritative and must never be overridden by model output.
            # Structured responses carry severity as a JSON "severity" key
            # (meta["severity_inferred"], parsed in _enrich -- a leading
            # "SEVERITY=" TEXT line would break JSON); the text rung keeps
            # the original leading-line convention, stripped BEFORE
            # validating so it can never count toward (or against)
            # min_lines/first-line checks.
            severity = alert.get("severity") or "unknown"
            severity_inferred = None
            if severity == "unknown":
                if structured:
                    severity_inferred = meta.get("severity_inferred")
                else:
                    severity_inferred, enrichment = parse_inferred_severity(enrichment)
                if severity_inferred:
                    severity = severity_inferred
                    # I1 fix: _run_structured_call's disposition gate ran
                    # BEFORE this point, keyed off the pre-inference source
                    # severity (always "unknown" here, disposition==
                    # "problem" -- so cause/checks were NOT stripped at call
                    # time). If the model's own inferred severity now makes
                    # the DELIVERED disposition non-"problem", re-apply the
                    # same deterministic line-filter to the already-rendered
                    # text -- normalize_enrichment is idempotent and its
                    # filter matches render_structured's fixed lead-ins, so
                    # this strips "Likely caused by"/"Next:" from BOTH the
                    # structured and free-text rungs in one spot.
                    inferred_disp = disposition(severity)
                    if inferred_disp != "problem":
                        enrichment = normalize_enrichment(enrichment, disposition=inferred_disp)
            # The structured path's ENTIRE validation gate is
            # validate_structured (already applied inside _enrich, before
            # render_structured produced this `enrichment` text) -- a
            # summary-only recovery is one legitimate line and must not be
            # rejected by validate_output/min_lines, which assume the
            # multi-line plain-text shape.
            if not structured and not self._validate(enrichment, min_lines=min_lines):
                raise _Fallback("validation")
            # Deadline may have fired while enrichment ran — discard the late
            # result rather than emit a raw+late-enriched duplicate.
            if deadline.expired():
                raise _Fallback("deadline during enrichment")
            if severity_inferred:
                # Auditability: mark that this severity came from the model,
                # not the source -- a subtle drill-down-only note (never in
                # the terse push headline, which only ever reads the first
                # line of `enrichment`). Chosen over a dedicated store
                # column/Envelope field as the lowest-footprint option: it
                # rides the existing `enrichment` text straight into the
                # delivered detail AND the store's `enrichment` audit column
                # (see _record_stats) with no schema/dataclass change.
                #
                # FIX 3: appended BEFORE the knowledge garnish below -- this
                # note is about the analysis itself, so it must stay attached
                # to it, not end up trailing the unrelated "General guidance"
                # addendum the knowledge plane may append after it.
                enrichment = f"{enrichment.rstrip()}\n\n(severity inferred, not reported by the source)"
            enrichment = self._garnish_with_knowledge(alert, enrichment, deadline, effective_depth)
            recurrence_count, window_label = self._recurrence_suffix(alert)
            sections_red = meta.get("sections_red") or {}
            # Mask secrets in the embedded raw — it egresses to the notification
            # channel (identifiers stay; it's the user's own channel).
            envelope = build_envelope(
                enrichment, self._redact(raw_text)[0],
                severity=severity,
                host=alert.get("host") or "", service=alert.get("service") or "",
                marker=False,
                recurrence_count=recurrence_count, window_label=window_label,
                sections_red=sections_red, evidence_max_bytes=self.evidence_max_bytes,
            )
            if sections_red:
                try:
                    envelope = _dc_replace(envelope, detail_html=build_detail_html(
                        envelope, sections_red=sections_red, cap_bytes=self.evidence_max_bytes))
                except Exception:
                    pass  # keep build_envelope's own detail_html rather than strand the alert
            return self._deliver_enriched(key, alert, envelope, sections_red, enrichment, usage, meta)
        except Exception as e:
            # ANY failure (LLM, validation, deadline, internal) -> raw + marker.
            return self._deliver_raw(key, raw_text, fail_stage=self._classify_failure(e), alert=alert)

    def _delivery_has_verbosity(self, verbosity):
        """Duck-typed `self.delivery.has_verbosity(verbosity)` -- see the
        `_BRIEF`/`_FULL` module constants' comment for why this doesn't just
        import the Dispatch class from the delivery ring and check
        `isinstance`. A delivery double that predates `has_verbosity` (i.e.
        doesn't have it at all) degrades to False, which is the correct
        "can't defer, can't follow-up" answer for a bare `.send()`-only
        double."""
        fn = getattr(self.delivery, "has_verbosity", None)
        return bool(fn(verbosity)) if fn is not None else False

    def _deliver_enriched(self, key, alert, envelope, sections_red, enrichment, usage, meta):
        """The enriched happy-path delivery, INCLUDING the Batch-C assist-plane
        deferral decision.

        Deferral (send brief now, hand the full/rich leg to the assist
        worker so it can carry an out-of-band insight) applies ONLY when
        every one of these holds: an assist plane is configured
        (`self.assist is not None`), this alert's severity/mode are eligible
        for it, AND at least one BRIEF-verbosity channel AND at least one
        FULL-verbosity channel are both configured -- deferral means "say
        something terse right now, say more later", which is meaningless
        with only one verbosity available.

        When there's no brief leg to defer past (e.g. `NUNCIO_DELIVERY=email`
        alone, all FULL), the alert ships in full immediately on this same
        30s path exactly like pre-Batch-C -- and if a FULL channel exists and
        assist is eligible, the assist plane still runs, delivering its
        result as a separate, clearly-labeled FOLLOW-UP message (never
        merged into -- and never re-sending -- the alert that already went
        out). With no FULL channel at all (brief-only, e.g. ntfy alone),
        there is nowhere to deliver even a follow-up, so assist never fires."""
        # BLOCKER 2b (Phase B): a best-effort, fail-OPEN duplicate-delivery
        # belt. The maintenance thread's cutoff and this method can, in a
        # narrow race, both decide to deliver the SAME key (see
        # nuncio.server.App._maintenance's cutoff docstring) -- re-check the
        # store status right before committing to delivery. A store hiccup
        # here (get_status raising) must NEVER block delivery -- that would
        # violate NEVER-LOSE for the sake of a de-dup nicety -- so any
        # exception is swallowed and delivery proceeds as normal.
        try:
            status = self.store.get_status(key)
            if status not in (None, "received"):
                return "skipped_duplicate"
        except Exception:
            pass
        # This method is only ever reached via the "enriched"-mode happy path
        # (process()'s bypass branch returns before enrichment is attempted
        # at all) -- so the mode checked against AssistTrack.eligible() is
        # always "enriched" here, never the raw self.mode attribute (which
        # could have drifted since this specific alert was ingested).
        #
        # has_full/has_brief are only even evaluated when an assist plane is
        # configured AND eligible -- every pre-Batch-C test double
        # (FakeDelivery et al.) implements `.send()` only, not
        # `.has_verbosity()`, and must keep working unchanged when
        # `self.assist` is None (the default) -- see `_delivery_has_verbosity`.
        assist_eligible = self.assist is not None and self.assist.eligible(envelope.severity, "enriched")
        has_full = has_brief = False
        if assist_eligible:
            has_full = self._delivery_has_verbosity(_FULL)
            has_brief = self._delivery_has_verbosity(_BRIEF)
        defer = assist_eligible and has_full and has_brief

        if defer:
            ok = self.delivery.send_brief(envelope)
            if ok:
                self.store.mark_delivered(key, "enriched")
                self._record_stats(key, outcome="enriched", tokens=usage,
                                    llm_ms=meta.get("llm_ms"),
                                    redaction_count=meta.get("redaction_count"),
                                    bundle_bytes=meta.get("bundle_bytes"),
                                    enrichment_text=enrichment,
                                    enrich_format=meta.get("enrich_format"))
                try:
                    self.store.record_stats(key, assist_status="deferred")
                except Exception:
                    pass
                context_text = self._build_assist_context(alert, sections_red, enrichment, envelope)
                if not self.assist.submit(key, envelope, context_text):
                    # Assist queue saturated -- deliver the rich leg right now
                    # with no insight rather than silently losing it. Status
                    # is recorded BEFORE the send (mirrors the orphan sweep's
                    # mark-before-send discipline in assist.py) so a crash
                    # between the two leaves the row terminally 'skipped'
                    # rather than stuck 'deferred' -- the next boot's sweep
                    # would otherwise treat a stuck 'deferred' row as an
                    # orphan and re-send the rich leg, duplicating it. The
                    # trade is symmetric: a crash before the send now loses
                    # the rich leg instead of duplicating it, which is the
                    # intended at-most-once posture for this leg (the primary
                    # alert is unaffected either way -- it already went out).
                    try:
                        self.store.record_stats(key, assist_status="skipped")
                    except Exception:
                        pass
                    self.delivery.send_full(envelope)
                return "enriched"
            # The brief leg failed entirely -- fall through to the normal
            # all-channel send below rather than stranding the alert.

        if self.delivery.send(envelope):
            self.store.mark_delivered(key, "enriched")
            self._record_stats(key, outcome="enriched", tokens=usage,
                                llm_ms=meta.get("llm_ms"),
                                redaction_count=meta.get("redaction_count"),
                                bundle_bytes=meta.get("bundle_bytes"),
                                enrichment_text=enrichment,
                                enrich_format=meta.get("enrich_format"))
            if assist_eligible and has_full:
                # No brief leg was (successfully) deferred past -- the alert
                # already went out in full above. The assist result, if any,
                # arrives later as a separate follow-up message.
                context_text = self._build_assist_context(alert, sections_red, enrichment, envelope)
                self.assist.submit(key, envelope, context_text, followup=True)
            return "enriched"
        return "delivery_failed"  # channel down: leave for drain

    def _build_assist_context(self, alert, sections_red, enrichment_text, envelope):
        """The (already-redacted) text handed to the assist plane, BEFORE
        the assist-plane scrubber runs (see nuncio.redactor.scrub_for_assist_plane,
        applied by AssistTrack's worker) -- this method decides WHAT goes in,
        not how it's further scrubbed.

        Posture is a data-exposure policy, read from `self.assist.posture`:
          - "generic": the alert's category + severity + this deployment's
            classification-table generic string for that category -- the
            SAME allowlisted, identifier-free strings the knowledge plane
            uses (see Router.route_knowledge). No alert text of any kind.
          - "scrubbed-real": the alert's own (already-redacted) content --
            headline, top evidence sections, and the private enrichment's
            first line -- run through the assist scrubber before it ever
            leaves the process.
        Never raises; degrades to a minimal generic string on any failure."""
        try:
            alert_class = (alert.get("category") if isinstance(alert, dict) else None) \
                or categorize(alert if isinstance(alert, dict) else {})
        except Exception:
            alert_class = "generic"
        posture = getattr(self.assist, "posture", "generic")
        if posture == "scrubbed-real":
            try:
                lines = [envelope.headline, f"severity: {envelope.severity}"]
                for name in ("correlated", "recurrence"):
                    text = (sections_red or {}).get(name)
                    if text:
                        lines.append(f"{name}: {text}")
                logs = (sections_red or {}).get("recent_logs")
                if logs:
                    head = "\n".join(logs.splitlines()[:20])
                    lines.append(f"recent_logs:\n{head}")
                first_line = next((ln.strip() for ln in (enrichment_text or "").splitlines() if ln.strip()), "")
                if first_line:
                    lines.append(f"analysis: {first_line}")
                return "\n\n".join(lines)
            except Exception:
                pass  # fall through to the generic string below
        table = getattr(self.assist, "classification_table", None) or {}
        generic_str = table.get(alert_class) or "a generic infrastructure issue"
        return f"category: {alert_class}\nseverity: {envelope.severity}\n{generic_str}"

    def drain_raw(self):
        """Deliver every not-yet-delivered alert as raw (never re-run enrichment).
        One poison row can never abort the drain (or crash-loop startup).
        Returns how many were drained."""
        n = 0
        for key, raw_text in self.store.undelivered():
            try:
                if self._deliver_raw(key, raw_text) == "raw":
                    n += 1
            except Exception:
                continue
        return n

    # --- internals ---

    def _recurrence_suffix(self, alert):
        """(count, window_label) for the headline's recurrence suffix --
        best-effort, wrapped so a store hiccup here can never affect
        delivery. Returns (0, "") on any failure or when the alert has no
        stable fingerprint."""
        try:
            fp = compute_fingerprint(alert)
            if not fp:
                return 0, ""
            count, _first_seen = self.store.fingerprint_stats(fp, self.fingerprint_window_s)
            window_label = f"{int(self.fingerprint_window_s // 3600)}h"
            return count, window_label
        except Exception:
            return 0, ""

    def _redact_field(self, v):
        """Redact one alert-dict value regardless of its JSON type. See the
        comment in `_enrich` for why non-strings go through json.dumps rather
        than str()/repr(). Returns (redacted_text, finding_count) — the count
        feeds the dashboard's `redaction_count` stat, and this is the one
        place every alert field's redaction findings are visible, so it's the
        natural place to tally them rather than re-deriving the count later."""
        if v is None:
            return None, 0
        if isinstance(v, str):
            text, findings = self._redact(v)
        else:
            try:
                text_in = json.dumps(v, sort_keys=True, default=str)
            except Exception:
                text_in = str(v)
            text, findings = self._redact(text_in)
        count = sum(f.get("count", 0) for f in findings) if findings else 0
        return text, count

    def _redact_alert_fields(self, alert):
        """Redact every field of `alert` (see `_redact_field`'s docstring for
        why non-strings go through json.dumps rather than str()/repr()).
        Returns `(red_alert, redaction_count)`. Extracted from `_enrich` so
        `_enrich_full` (Phase B) can build its own redacted alert copy
        through the exact same discipline."""
        red_alert = {}
        redaction_count = 0
        for k, v in alert.items():
            text, count = self._redact_field(v)
            red_alert[k] = text
            redaction_count += count
        return red_alert, redaction_count

    def _use_structured(self):
        """Phase A format ladder gate: attempt the structured-JSON contract
        only when configured "auto" AND this LLMClient's capability cache
        hasn't already recorded that its endpoint rejects response_format
        (`None` = untried, `True`/`False` = known). The cache lives on the
        CLIENT (not the engine) so it persists across alerts and resets
        exactly when the client itself is rebuilt (see
        nuncio.config._LLM_ROUTER_KEYS)."""
        return (
            self.enrich_format == "auto"
            and getattr(self.llm, "_json_object_supported", None) is not False
        )

    def _gather_standard(self, alert, red_alert, deadline, key, use_structured, seed_sections=None):
        """The standard (non-deep) Level-B gather + message-build, shared by
        `_enrich` and `_enrich_full`'s degraded (tight-budget) path.

        `seed_sections`, when given (Phase B only -- the store-only
        correlated/recurrence/history sections `_enrich_full` already
        computed before this is called), is merged in BEFORE the network
        gather's own sections so a network collector's result for the same
        name (unusual, but not impossible) wins; this is also what lets the
        degraded full-depth path ship the `history` section even when there
        isn't enough budget left to gather anything else.

        Returns `(messages, sections_red, bundle_bytes, redaction_count)` --
        `redaction_count` here is only the DELTA contributed by bundle
        sections (the caller already has the alert-field count from
        `_redact_alert_fields`)."""
        sections_red = dict(seed_sections or {})
        redaction_count = 0
        if self.gatherer is None:
            return self._build_messages(red_alert, structured=use_structured), sections_red, None, redaction_count
        # Gather read-only context, redact EACH SECTION individually (one
        # pass), then re-assemble the bundle from the already-redacted
        # sections -- this is the SOLE source of both the prompt bundle and
        # the envelope's structured evidence sections, so there is exactly
        # one redaction pass, never a window where an unredacted section
        # could reach either. Clamp gathering to the remaining deadline
        # (reserve time for the LLM call); if too little budget remains,
        # skip gathering entirely.
        gather_budget = min(self.gatherer.timeout_s, deadline.remaining() - self.gather_reserve_s)
        bundle_bytes = None
        gathered = gather_budget >= 1.0
        if gathered:
            _, sections = self.gatherer.gather(
                alert, key, self._wall_clock(), timeout=gather_budget, return_sections=True)
            for name, text in sections.items():
                t, findings = self._redact(text)
                sections_red[name] = t
                redaction_count += sum(f.get("count", 0) for f in findings) if findings else 0
        # A bundle is worth assembling/persisting either when the network
        # gather actually ran (matches pre-Phase-B `_enrich` exactly,
        # regardless of whether it found anything -- an intentional
        # unconditional audit-trail write) OR when seed_sections (Phase B's
        # store-only correlated/recurrence/history) gave us something even
        # without a network gather this time.
        if gathered or seed_sections:
            bundle_red = assemble_bundle(sections_red, self.gatherer.max_bytes)
            bundle_bytes = len(bundle_red.encode("utf-8", errors="ignore"))
            try:
                self.store.set_bundle(key, bundle_red)  # audit trail (redacted only)
            except Exception:
                pass
        else:
            bundle_red = ""  # not enough budget to gather, no seed either -> empty bundle
        messages = self._build_messages_b(red_alert, bundle_red, structured=use_structured)
        return messages, sections_red, bundle_bytes, redaction_count

    def _enrich(self, alert, deadline, key):
        red_alert, redaction_count = self._redact_alert_fields(alert)
        use_structured = self._use_structured()
        messages, sections_red, bundle_bytes, extra_red = self._gather_standard(
            alert, red_alert, deadline, key, use_structured)
        redaction_count += extra_red
        content, usage, llm_ms, enrich_format, severity_inferred = self._run_structured_call(
            messages, deadline, use_structured, alert=alert)
        meta = {
            "redaction_count": redaction_count, "bundle_bytes": bundle_bytes, "llm_ms": llm_ms,
            "sections_red": sections_red, "enrich_format": enrich_format,
            "severity_inferred": severity_inferred,
        }
        return content, usage, meta

    def _enrich_full(self, alert, deadline, key):
        """Phase B, full depth (the default): recent-alert-history
        correlation + a bounded 2-call pipeline (fast plain-text triage, then
        a deep RCA call over a richer context bundle). Structured so that:
          - the store-only sections (correlated/recurrence/history -- no
            network I/O, so even a bare/all-null-collector install gets real
            cross-alert signal) ALWAYS run, regardless of remaining budget;
          - the network gather and the call-count degrade INDEPENDENTLY of
            each other, so full is NEVER worse than low:
              * not enough time left for the 2-call flow at all -> degrade
                to the exact standard single Level-B call `_enrich` would
                have made, just with the store-only sections (incl.
                `history`) merged into its bundle -- see `_gather_standard`.
              * enough time for the network gather + deep bundle but not
                the full 30s RCA call -> a single tight-bound RCA attempt
                (no retry) rather than none at all.
              * genuinely out of time even for that -> `_Fallback("deadline")`
                (-> the caller's existing raw-fallback path, same as any
                other failure -- NEVER-LOSE is unaffected).
          - Call 2 (deep RCA) reuses `_run_structured_call` -- the SAME
            Phase-A structured/redact/validate ladder every other call in
            this engine uses, so its output is structured-JSON-rendered,
            redacted, and validated exactly like a standard call.

        Ledger at the defaults (NUNCIO_FULL_BUDGET_S=60): 10s gather + 15s
        triage + 30s RCA + 3s delivery reserve = 58s <= 60s."""
        now = self._wall_clock()
        red_alert, redaction_count = self._redact_alert_fields(alert)
        use_structured = self._use_structured()

        # 1. Store-only sections -- ALWAYS computed (cheap, no network I/O),
        # regardless of remaining budget. A name missing from the gatherer's
        # `collectors` dict (a bare/hand-built gatherer, e.g. a test double)
        # is silently skipped, never fatal -- this pipeline must degrade
        # gracefully on a gatherer that only implements `.gather()`.
        sections_red = {}
        collectors = getattr(self.gatherer, "collectors", None) or {}
        for name in ("correlated", "recurrence", "history"):
            fn = collectors.get(name)
            if fn is None:
                continue
            try:
                text = fn(alert, key, now)
            except Exception:
                continue
            t, findings = self._redact(text)
            sections_red[name] = t
            redaction_count += sum(f.get("count", 0) for f in findings) if findings else 0

        remaining = deadline.remaining()
        if remaining - _FULL_POST_GATHER_RESERVE_S < 1.0:
            # 4a-else: not enough time for the 2-call flow -- degrade to the
            # standard single Level-B path, WITH the store-only sections
            # (incl. `history`) merged in.
            messages, sections_red, bundle_bytes, extra_red = self._gather_standard(
                alert, red_alert, deadline, key, use_structured, seed_sections=sections_red)
            redaction_count += extra_red
            content, usage, llm_ms, enrich_format, severity_inferred = self._run_structured_call(
                messages, deadline, use_structured, alert=alert)
            meta = {
                "redaction_count": redaction_count, "bundle_bytes": bundle_bytes, "llm_ms": llm_ms,
                "sections_red": sections_red, "enrich_format": enrich_format,
                "severity_inferred": severity_inferred,
            }
            return content, usage, meta

        # 4a: full network gather (deep collector profile) -- clamped to
        # BOTH the fixed 10s cap and whatever's left after reserving 48s for
        # the rest of the ladder.
        gather_budget = min(_FULL_GATHER_BOUND_S, remaining - _FULL_POST_GATHER_RESERVE_S)
        try:
            _, extra_sections = self.gatherer.gather(
                alert, key, now, timeout=gather_budget, return_sections=True, profile="full")
        except Exception:
            extra_sections = {}
        for name, text in extra_sections.items():
            if name in ("correlated", "recurrence", "history"):
                continue  # store-only, already handled above -- never double-count/overwrite
            t, findings = self._redact(text)
            sections_red[name] = t
            redaction_count += sum(f.get("count", 0) for f in findings) if findings else 0
        deep_cap = min(4 * self.gatherer.max_bytes, _FULL_MAX_BUNDLE_BYTES)
        bundle_red = assemble_bundle(sections_red, deep_cap)
        bundle_bytes = len(bundle_red.encode("utf-8", errors="ignore"))
        try:
            self.store.set_bundle(key, bundle_red)  # audit trail (redacted only)
        except Exception:
            pass

        # 4b: triage call -- best-effort, PLAIN TEXT, never a fallback
        # trigger. `sections_red` is deliberately store-only (no logs/
        # metrics); `build_full_triage_messages` additionally strips the
        # heavy `details`/`perfdata` extras off `red_alert`'s own ## Alert
        # block, so the call as a whole stays log/metric-free (see that
        # function's docstring).
        triage_notes, triage_usage, triage_llm_ms = None, None, 0.0
        if deadline.remaining() >= _FULL_TRIAGE_MIN_REMAINING_S:
            triage_bound = min(_FULL_TRIAGE_BOUND_S, deadline.remaining() - _FULL_TRIAGE_RESERVE_S)
            if triage_bound >= 1.0:
                try:
                    triage_messages = build_full_triage_messages(red_alert, sections_red)
                    t_content, t_usage, t_ms = self._call_bounded(
                        triage_messages, deadline, None, bound=triage_bound)
                    triage_notes = (t_content or "").strip() or None
                    triage_usage, triage_llm_ms = t_usage, (t_ms or 0.0)
                except Exception:
                    triage_notes = None

        triage_block = ""
        if triage_notes:
            # Sentinel-neutralize the triage output before embedding it as
            # analyst notes in call 2's prompt -- it's model-generated text
            # and must not be able to forge/close the «TRIAGE-START/END»
            # framing early (same discipline as build_level_b_messages'
            # «BUNDLE-START/END» neutralization of the untrusted bundle).
            neutralized = (triage_notes.replace("«TRIAGE-START»", "[triage-start]")
                                        .replace("«TRIAGE-END»", "[triage-end]"))
            triage_block = (
                "\n\n## Analyst notes (automated triage pass — may be wrong; verify against "
                "the evidence, do not repeat verbatim)\n«TRIAGE-START»\n" + neutralized + "\n«TRIAGE-END»"
            )

        # 4c: deep RCA call -- the SAME Phase-A structured ladder (via
        # `_run_structured_call`), so its output is structured/redacted/
        # validated exactly like a standard call.
        remaining2 = deadline.remaining()
        rca_bound = min(_FULL_RCA_BOUND_S, remaining2 - _FULL_RCA_DELIVERY_RESERVE_S)
        messages = self._build_messages_b(red_alert, bundle_red + triage_block,
                                          structured=use_structured, multi_correlation=True)
        if rca_bound < _FULL_RCA_TIGHT_MIN_S:
            # Re-derived per the spec's literal wording ("bound = min(30,
            # remaining-3); if bound < 8 -> attempt ONE call iff
            # remaining-3 >= 8, else _Fallback"). NOTE for future
            # maintainers: because `rca_bound = min(30, remaining2 - 3)` and
            # 30 is never < 8, `rca_bound < 8` can only be true when
            # `remaining2 - 3 < 8` -- i.e. `tight_bound` below is ALWAYS
            # equal to `rca_bound` inside this branch, so the "attempt ONE
            # call" arm is unreachable as literally specified (this branch
            # always falls through to `_Fallback("deadline")`). Kept exactly
            # as specified (defensive, not a bug) rather than restructured,
            # so a future genuine distinction between the two bounds (e.g. a
            # deliberately looser tight-path allowance) is a small, obvious
            # diff rather than a rewrite.
            tight_bound = remaining2 - _FULL_RCA_DELIVERY_RESERVE_S
            if tight_bound < _FULL_RCA_TIGHT_MIN_S:
                raise _Fallback("deadline")
            content, usage, llm_ms, enrich_format, severity_inferred = self._run_structured_call(  # pragma: no cover
                messages, deadline, use_structured, alert=alert, bound=tight_bound, allow_retry=False)
        else:
            content, usage, llm_ms, enrich_format, severity_inferred = self._run_structured_call(
                messages, deadline, use_structured, alert=alert, bound=rca_bound,
                retry_cost=rca_bound + _FULL_RCA_DELIVERY_RESERVE_S, allow_retry=True)

        meta = {
            "redaction_count": redaction_count, "bundle_bytes": bundle_bytes,
            "llm_ms": (triage_llm_ms or 0.0) + (llm_ms or 0.0),
            "sections_red": sections_red, "enrich_format": enrich_format,
            "severity_inferred": severity_inferred,
        }
        return content, _sum_usage(triage_usage, usage), meta

    def _run_structured_call(self, messages, deadline, use_structured, alert=None, bound=None,
                              retry_cost=None, allow_retry=True):
        """The parse/validate/redact/render half of the format ladder,
        wrapping `_call_llm_with_ladder`'s LLM-call half -- extracted from
        `_enrich` so `_enrich_full`'s deep RCA call (and its degraded/tight
        single-call fallbacks) go through the EXACT same structured contract
        as every standard call. Returns
        `(content, usage, llm_ms, enrich_format, severity_inferred)`.

        `alert` (Phase 2) is THIS call's alert dict, used ONLY to compute its
        determinism-doctrine disposition (nuncio.model.disposition, keyed off
        `alert["severity"]`) -- the HARD gate: a "recovery"/"info" disposition
        forces `likely_cause`/`checks` empty on the structured rung (before
        `render_structured` ever sees them) and strips any "Likely caused
        by"/"Next:" line on the text rung, regardless of what the model
        returned. `alert=None` (a direct/defensive call with no alert in
        scope) degrades to disposition "problem" -- i.e. no gating -- rather
        than raising; every real call site in this engine passes `alert`."""
        disp = disposition((alert or {}).get("severity") or "unknown")
        content, usage, llm_ms, capability_recall = self._call_llm_with_ladder(
            messages, deadline, use_structured, bound=bound, retry_cost=retry_cost, allow_retry=allow_retry,
        )

        enrich_format = "text"
        severity_inferred = None
        if use_structured and not capability_recall:
            # Parse discipline: only content that LOOKS JSON-intended (starts
            # with "{", after stripping whitespace + one optional ```json
            # fence) is treated as structured -- anything else is an
            # endpoint that ignored response_format and wrote prose, which
            # falls straight through to the text rung below rather than
            # being force-fit into JSON.
            parsed = self._parse_structured_content(content)
            if parsed is not None:
                fields = validate_structured(parsed)
                if fields is None:
                    raise _Fallback("structured validation: validate_structured")
                for k in ("summary", "likely_cause"):
                    fields[k] = self._redact(fields[k])[0]
                if isinstance(fields["correlation"], str):
                    fields["correlation"] = self._redact(fields["correlation"])[0]
                elif isinstance(fields["correlation"], list):
                    fields["correlation"] = [self._redact(c)[0] for c in fields["correlation"]]
                fields["checks"] = [self._redact(c)[0] for c in fields["checks"]]
                if disp != "problem":
                    # Determinism doctrine's HARD gate: even a fully
                    # non-compliant model that ignored the prompt-side
                    # addendum (nuncio.prompt._DISPOSITION_ADDENDUM) and
                    # returned a cause/checks anyway cannot ship them on a
                    # recovery or info alert -- enforced here, in code,
                    # AFTER redaction and BEFORE render_structured.
                    fields["likely_cause"] = ""
                    fields["checks"] = []
                content = render_structured(fields)
                enrich_format = "structured"
                sev = parsed.get("severity")
                if isinstance(sev, str) and sev.strip().lower() in _CANONICAL_SEVERITIES:
                    severity_inferred = sev.strip().lower()

        if enrich_format != "structured":
            # Text rung -- reached via: NUNCIO_ENRICH_FORMAT=text, a
            # capability re-call (always forced text, regardless of shape),
            # or structured-requested content that turned out to be prose.
            # NEW in Phase A: normalize_enrichment() strips leftover
            # report-style formatting, and the response is now redacted
            # (previously only the alert fields going INTO the prompt were
            # redacted -- this is defense-in-depth against a model echoing
            # something from the prompt back out). Phase 2: `disposition=disp`
            # is the text rung's half of the same hard gate -- drops any
            # "Likely caused by"/"Next:" line for a non-"problem" disposition.
            content = normalize_enrichment(content, disposition=disp)
            content = self._redact(content)[0]

        return content, usage, llm_ms, enrich_format, severity_inferred

    def _call_llm_with_ladder(self, messages, deadline, use_structured, bound=None,
                               retry_cost=None, allow_retry=True):
        """The LLM-call half of the format ladder (see nuncio.prompt's module
        docstring for the parse/validate half). Returns
        `(content, usage, llm_ms, capability_recall)` -- `capability_recall`
        is True only when this call is the at-most-once, no-response_format
        re-call made after a capability-detection 400/422; the caller MUST
        treat that response as text-intended (rung 4) unconditionally,
        never re-running the JSON-parse discipline on it.

        `bound` (Phase B), when given, overrides `self.per_attempt_s` as the
        per-attempt wall-clock bound passed to `_call_bounded` (both the
        first attempt and any retry use the SAME bound). `retry_cost`,
        when given, overrides the default `self.per_attempt_s +
        self.delivery_budget_s` cost check for `deadline.can_afford()`.
        `allow_retry=False` (Phase B's tight-budget/no-retry call sites)
        disables BOTH retry branches below unconditionally, regardless of
        budget -- "at most one attempt, period".

        Retry semantics, in priority order (skipped entirely when
        `allow_retry=False`):
          1. capability-detection failure (400/422, or "response_format" in
             the body excerpt) while `use_structured` -- flips
             `self.llm._json_object_supported` to False (persists on the
             CLIENT, so every later alert on this engine skips the
             structured attempt entirely until the client is rebuilt, e.g.
             by a live settings change -- see nuncio.config's
             _LLM_ROUTER_KEYS), then re-calls ONCE without response_format
             IFF the deadline can still afford one more attempt + delivery;
             otherwise re-raises (-> raw fallback for THIS alert only).
          2. any other retryable LLMError (5xx/429) -- the pre-existing
             exactly-one-retry behavior, with the SAME response_format (the
             format wasn't the problem)."""
        retry_cost = retry_cost if retry_cost is not None else self.per_attempt_s + self.delivery_budget_s
        response_format = {"type": "json_object"} if use_structured else None
        try:
            content, usage, llm_ms = self._call_bounded(messages, deadline, response_format, bound=bound)
            return content, usage, llm_ms, False
        except LLMError as e:
            is_capability_failure = use_structured and (
                e.status in (400, 422) or "response_format" in (e.body_excerpt or "")
            )
            if is_capability_failure:
                self.llm._json_object_supported = False
                if not allow_retry or not deadline.can_afford(retry_cost):
                    raise
                content, usage, llm_ms = self._call_bounded(messages, deadline, None, bound=bound)
                return content, usage, llm_ms, True
            if allow_retry and e.retryable and deadline.can_afford(retry_cost):
                content, usage, llm_ms = self._call_bounded(messages, deadline, response_format, bound=bound)
                return content, usage, llm_ms, False
            raise

    def _parse_structured_content(self, content):
        """Try to parse `content` as the structured-JSON contract (see
        nuncio.prompt._JSON_OUTPUT_FORMAT). Returns a dict on success, or
        None when `content` is not JSON-intended at all (doesn't start with
        "{" after stripping whitespace + one optional ```json fence) -- the
        caller routes a None to the text rung.

        Raises `_Fallback` when content IS JSON-intended (starts with "{")
        but fails to parse even after a brace-extraction retry -- this must
        NEVER fall through to the text rung: a truncated
        `{"summary": "...` must never ship as literal JSON garbage in a
        delivered notification."""
        stripped = (content or "").strip()
        fence = re.match(r"^```(?:json)?\s*\n?(.*?)\n?```$", stripped, re.DOTALL)
        if fence:
            stripped = fence.group(1).strip()
        if not stripped.startswith("{"):
            return None
        try:
            return json.loads(stripped)
        except ValueError:
            pass
        start, end = stripped.find("{"), stripped.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(stripped[start:end + 1])
            except ValueError:
                pass
        raise _Fallback("structured validation: json_parse")

    def _call_bounded(self, messages, deadline, response_format=None, bound=None):
        """Run the LLM call with a HARD wall-clock bound so a hung/slow-drip
        response can't freeze the worker past the deadline (urllib's timeout is
        per-socket-op, not total). On timeout the call is abandoned (its thread
        leaks until the socket times out) and we fall back to raw. Uses the
        shared `nuncio.deadline.run_bounded` abandon-the-thread primitive (also
        used by `_garnish_with_knowledge` below and by
        `nuncio.assist.AssistTrack`'s worker -- one implementation, every hard-
        bounded outbound call in this codebase).

        Returns (content, usage, elapsed_s). `nuncio.llm.LLMClient.enrich`
        returns `(content, usage)`; test doubles (FakeLLM/ScriptedLLM across
        the existing test suite) predate that and return a bare string --
        both shapes are accepted here (`usage` degrades to None for the bare-
        string case) so this stays a purely additive change for every caller
        that doesn't care about usage. `response_format`, when not None, is
        forwarded to `self.llm.enrich` (Phase A structured-JSON ladder, see
        `_call_llm_with_ladder`). `bound` (Phase B), when given, overrides
        `self.per_attempt_s` as this specific attempt's per-call cap (e.g.
        the triage/RCA calls' own tighter or looser bounds in
        `_enrich_full`) -- still always clamped to `deadline.remaining()`,
        never allowed to run past the alert's own deadline."""
        eff_per_attempt = bound if bound is not None else self.per_attempt_s
        bound = min(eff_per_attempt, max(0.1, deadline.remaining()))
        t0 = self._wall_clock()
        try:
            # MUST-FIX 1: thread THIS attempt's own wall-clock bound through
            # as the HTTP socket timeout too -- a non-streaming chat
            # completion sends nothing until generation finishes, so without
            # this the socket would time out at the client's fixed
            # construction-time NUNCIO_LLM_TIMEOUT_S (default 10s) regardless
            # of a deliberately larger per-call bound (e.g. the full-depth
            # RCA call's up-to-30s bound), capping the deep RCA call's
            # actual model time at 10s even when it was budgeted 30s.
            if response_format is not None:
                raw = run_bounded(
                    lambda: self.llm.enrich(messages, response_format=response_format, timeout=bound), bound)
            else:
                raw = run_bounded(lambda: self.llm.enrich(messages, timeout=bound), bound)
        except TimeoutError:
            raise LLMError("hard timeout", retryable=False)
        elapsed = max(0.0, self._wall_clock() - t0)
        if isinstance(raw, tuple) and len(raw) == 2:
            content, usage = raw
        else:
            content, usage = raw, None
        return content, usage, elapsed

    def _garnish_with_knowledge(self, alert, enrichment_text, deadline, depth=None):
        """Best-effort knowledge-plane garnish, called AFTER the private-plane
        enrichment has already been produced and validated. Structurally
        privacy-preserving: the ONLY thing that can ever reach
        `self.knowledge_llm` is `self.router.classification_table`'s VALUE for
        the alert's class (an operator-authored, generic, identifier-free
        string) — never `alert`, `enrichment_text`, or anything derived from
        them. `Router.route_knowledge` (see nuncio/router.py) is what enforces
        the allowlist-by-construction: it returns None for a disabled plane or
        an unmatched class, and this method has no other way to reach the
        knowledge client.

        The alert's "class" is its `category` field if the source adapter
        supplied one, else the same `categorize()` heuristic used elsewhere
        (hardware/storage/network/container/generic) — the classification
        table's keys are expected to match one of those.

        `depth` (Phase C) is THIS alert's effective enrichment depth --
        threaded from `process()` exactly like `mode`/`depth` are threaded
        everywhere else in this engine, so a live NUNCIO_ENRICH_DEPTH settings
        change can never retroactively change which alert this decision was
        made for. Defaults to `self.depth` for direct callers (tests, a
        hand-rolled invocation) that don't track it per-alert.

        Redundancy skip (honest default): when `depth == "full"` AND
        `self.router.knowledge_redundant_with_private` is True (the
        knowledge plane's effective endpoint+model, after inheritance, is
        identical to the private plane's -- see
        nuncio.config._knowledge_redundant_with_private), the garnish is
        SKIPPED. At that point the deep full-depth RCA call has already run
        the SAME model against the full real context bundle -- a generic,
        context-free same-model garnish would only add tokens and latency
        for zero additional information. The garnish therefore meaningfully
        fires only in `low` depth, or when the knowledge plane is pointed at
        a genuinely distinct endpoint/model (see build_plane_info's
        "active_when").

        Never raises, never blocks past the alert's own deadline (bounded the
        same way as the private-plane call), and on ANY failure — disabled,
        no match, timeout, transport error, empty response — silently returns
        `enrichment_text` unchanged. The knowledge plane is a garnish, never a
        delivery dependency."""
        if self.router is None or self.knowledge_llm is None:
            return enrichment_text
        effective_depth = depth if depth is not None else self.depth
        if effective_depth == "full" and getattr(self.router, "knowledge_redundant_with_private", False):
            log.debug(
                "knowledge-plane garnish skipped: full depth + knowledge endpoint/model identical to the "
                "private plane (redundant with the deep RCA call already run)"
            )
            return enrichment_text
        try:
            alert_class = (alert.get("category") if isinstance(alert, dict) else None) \
                or categorize(alert if isinstance(alert, dict) else {})
            routed = self.router.route_knowledge(alert_class)
            if routed is None:
                return enrichment_text
            _alias, generic_prompt = routed
            generic_prompt = scrub_for_knowledge_plane(generic_prompt)[0]
            bound = min(self.per_attempt_s, deadline.remaining() - self.delivery_budget_s)
            if bound < 1.0:
                return enrichment_text  # not enough budget left -- skip the garnish entirely
            try:
                raw = run_bounded(lambda: self.knowledge_llm.enrich(build_knowledge_messages(generic_prompt)), bound)
            except Exception:
                return enrichment_text
            guidance = raw[0] if isinstance(raw, tuple) and len(raw) == 2 else raw
            # Phase C: pass the guidance through BOTH scrub_for_knowledge_plane
            # (identifier stripping -- unchanged, existing behavior) AND
            # normalize_enrichment (Phase A's markdown/heading cleanup) before
            # it's appended, so a knowledge-plane response that ignores the
            # "no markdown" prompt instruction can never reintroduce a
            # "**SUMMARY**"-style heading into the delivered message.
            guidance = scrub_for_knowledge_plane((guidance or "").strip())[0]
            # Phase 2: same disposition gate as the private-plane call --
            # guidance appended to a recovery/info alert must not prescribe
            # fixes for a problem that either ended or was never one.
            disp = disposition(alert.get("severity") or "unknown") if isinstance(alert, dict) else "problem"
            guidance = normalize_enrichment(guidance, disposition=disp).strip()
            if not guidance:
                return enrichment_text
            return f"{enrichment_text.rstrip()}\n\n---\n{KNOWLEDGE_GUIDANCE_HEADER}:\n{guidance}"
        except Exception:
            return enrichment_text

    def _deliver_raw(self, key, raw_text, marker=True, fail_stage=None, alert=None):
        """The structurally-trivial raw path: a redactor or envelope-build
        exception must NOT strand the alert. Degrade to verbatim raw
        (already secret-masked at ingest, so this can't leak) rather than
        raise.

        Always marks the store 'raw' on success -- the only terminal raw
        status this store knows about. `marker` controls whether the
        RAW_FALLBACK_MARKER is prepended -- every caller EXCEPT bypass's own
        call site, incl. the maintenance thread and `drain_raw`, wants the
        marker; `process()`'s bypass branch passes `marker=False` for a
        plain, unmarked pass-through. `fail_stage` is the dashboard's
        best-effort record of WHY this alert took the raw path -- optional,
        and left None (unknown) rather than guessed when the caller
        genuinely doesn't know (e.g. the maintenance/drain safety nets,
        which can't distinguish their several possible root causes from
        here). `alert`, when the caller has it (process()'s except-branch
        and bypass branch), supplies severity/host/service for the
        headline; the bare call sites (drain_raw, maintenance, worker
        deadline) don't have it and degrade to a best-effort store lookup."""
        # BLOCKER 2b (Phase B): same fail-OPEN duplicate-delivery belt as
        # `_deliver_enriched` above -- see that method's comment for the
        # full reasoning (the maintenance-thread/worker race this closes,
        # and why a store hiccup here must never block delivery).
        try:
            status = self.store.get_status(key)
            if status not in (None, "received"):
                return "skipped_duplicate"
        except Exception:
            pass
        try:
            safe = self._redact(raw_text)[0]
        except Exception:
            safe = raw_text
        try:
            if alert is not None:
                severity = alert.get("severity") or "unknown"
                host = alert.get("host") or ""
                service = alert.get("service") or ""
            else:
                try:
                    severity = self.store.get_severity(key) or "unknown"
                except Exception:
                    severity = "unknown"
                host = ""
                service = ""
            summary = next((ln.strip() for ln in safe.splitlines() if ln.strip()), "")
            headline = build_headline(severity, host, service, summary)
            marker_line = RAW_FALLBACK_MARKER + "\n" if marker else ""
            envelope = Envelope(
                severity=severity, host=host, service=service,
                headline=headline, summary=summary, detail=marker_line + safe,
                detail_html=None, notify_type=severity_to_notify_type(severity), marker=marker,
            )
        except Exception:
            marker_line = RAW_FALLBACK_MARKER + "\n" if marker else ""
            envelope = Envelope(
                severity="unknown", host="", service="",
                headline="? — alert", summary="",
                detail=marker_line + str(raw_text),
                detail_html=None, notify_type="3", marker=marker,
            )
        if self.delivery.send(envelope):
            try:
                self.store.mark_delivered(key, "raw")
            except Exception:
                pass  # delivered; a failed mark only risks an accepted drain dup
            self._record_stats(key, outcome="raw", fail_stage=fail_stage)
            return "raw"
        return "delivery_failed"

    def _classify_failure(self, exc):
        """Best-effort `fail_stage` classification
        from the exception that sent an alert down the raw path. Never
        raises -- worst case, "internal" (still true: SOMETHING internal
        failed)."""
        try:
            if isinstance(exc, _Fallback):
                msg = str(exc)
                if "deadline" in msg:
                    return "deadline"
                if "validation" in msg:
                    return "validate"
                return "internal"
            if isinstance(exc, LLMError):
                return "llm"
        except Exception:
            pass
        return "internal"

    def _record_stats(self, key, outcome=None, fail_stage=None, tokens=None,
                       llm_ms=None, redaction_count=None, bundle_bytes=None,
                       enrichment_text=None, enrich_format=None):
        """Best-effort dashboard-stats write.

        HARD RULE (see the module docstring): every call site invokes this
        strictly AFTER the delivery-defining action (a successful
        `delivery.send()` + `store.mark_delivered()`)
        has already happened -- so a failure HERE can only lose a stats row,
        never the alert itself. This method additionally never raises on its
        own (store I/O error, whatever) so it can never turn a successful
        delivery into an unhandled exception that would incorrectly bubble
        into an outer try/except and trigger a duplicate send."""
        try:
            fields = {}
            if outcome is not None:
                fields["outcome"] = outcome
            if fail_stage is not None:
                fields["fail_stage"] = fail_stage
            if llm_ms is not None:
                fields["llm_ms"] = int(llm_ms * 1000)
            if redaction_count is not None:
                fields["redaction_count"] = redaction_count
            if bundle_bytes is not None:
                fields["bundle_bytes"] = bundle_bytes
            if enrichment_text is not None:
                fields["enrichment"] = enrichment_text
            if enrich_format is not None:
                fields["enrich_format"] = enrich_format
            if tokens:
                if tokens.get("prompt_tokens") is not None:
                    fields["tokens_in"] = tokens["prompt_tokens"]
                if tokens.get("completion_tokens") is not None:
                    fields["tokens_out"] = tokens["completion_tokens"]
            created = self.store.get_created_at(key)
            if created is not None:
                fields["latency_ms"] = int(max(0.0, self._wall_clock() - created) * 1000)
            if fields:
                self.store.record_stats(key, **fields)
        except Exception:
            pass
