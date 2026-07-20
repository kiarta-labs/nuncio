"""Context gatherer.

The gatherer decides what to fetch (never the LLM), from a fixed per-category
collector list keyed off structured alert fields. Collectors run concurrently in
DAEMON threads bounded by a shared semaphore (so a hung read-only client can't
leak threads unboundedly or hang `docker stop`); any that are slow/error degrade
to a «context unavailable» marker. Output is the assembled, capped bundle.
"""
import threading
import time

from nuncio.bundle import assemble_bundle
from nuncio.collectors import UNAVAIL
# categorize()/score_categories() live in nuncio.model so the core
# categorization logic is shared with source adapters and the dashboard
# without importing gatherer.py. Re-exported here for backward compatibility
# (existing importers of nuncio.gatherer.categorize keep working).
from nuncio.model import (  # noqa: F401 — re-exported for back-compat
    CATEGORY_PRIORITY as _PRIORITY,
    SECONDARY_MIN as _SECONDARY_MIN,
    categorize,
    score_categories,
)

# Per-category collector selection. 'correlated' and 'recurrence' are always
# included (recurrence needs only the store's own fingerprint index, so even
# a bare install gets it for free -- same reasoning as 'correlated').
_CATEGORY_COLLECTORS = {
    "container": ["recent_logs", "container_state", "correlated", "recurrence"],
    "storage": ["recent_logs", "metrics", "correlated", "recurrence"],
    "hardware": ["kernel", "metrics", "correlated", "recurrence"],
    "network": ["metrics", "recent_logs", "correlated", "recurrence"],
    "generic": ["recent_logs", "correlated", "recurrence"],
}


class Gatherer:
    def __init__(self, collectors, timeout_s=5.0, max_bytes=16000, max_concurrency=8,
                 full_collectors=None):
        # collectors: {name: callable(alert, alert_key, now) -> section_text}
        self.collectors = collectors
        # full_collectors (Phase B, optional): a DEEPER-profile implementation
        # per name (wider log windows, more correlation candidates, etc --
        # see nuncio.config.build_gatherer). A name absent from this dict
        # degrades per-name to the standard `collectors` closure (see
        # gather()'s docstring) rather than being dropped -- "full" is never
        # worse than "low" just because one collector has no deep variant.
        self.full_collectors = full_collectors or {}
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self._sem = threading.BoundedSemaphore(max_concurrency)

    def select(self, alert, profile="low"):
        """Primary category's collectors, plus those of any secondary category
        scoring >= _SECONDARY_MIN (mixed-signal alerts get the union), deduped
        in stable order. Still fully deterministic — never LLM-driven.

        `profile="full"` (Phase B) selects against the union of
        `full_collectors` and `collectors` (a name usable via either pool
        counts as selectable -- the per-name degrade happens in `gather()`,
        not here)."""
        scores = score_categories(alert)
        primary = categorize(alert)
        names = list(_CATEGORY_COLLECTORS.get(primary, _CATEGORY_COLLECTORS["generic"]))
        for cat in _PRIORITY:
            if cat != primary and scores.get(cat, 0) >= _SECONDARY_MIN:
                for n in _CATEGORY_COLLECTORS.get(cat, []):
                    if n not in names:
                        names.append(n)
        if profile == "full":
            return [n for n in names if n in self.full_collectors or n in self.collectors]
        return [n for n in names if n in self.collectors]

    def gather(self, alert, alert_key, now, timeout=None, return_sections=False, profile="low"):
        """Run selected collectors concurrently, bounded by `timeout` (defaults to
        self.timeout_s; the engine clamps it to the remaining deadline).

        `return_sections=True` additionally returns the raw per-collector
        results dict (post-degradation, pre-assembly) as
        `(bundle_str, dict(results))` -- so a caller can redact each section
        individually before re-assembling (see Engine._enrich). Default
        `False` keeps the return byte-identical to every pre-existing caller
        (just the assembled bundle string).

        `profile="full"` (Phase B, default remains "low" -- byte-identical
        to pre-Phase-B behavior) runs each selected collector's
        `full_collectors` implementation when one exists, degrading
        per-collector-name to the standard `collectors` implementation when
        it doesn't -- never a missing/None section just because a deep
        variant wasn't wired for that one name."""
        timeout = self.timeout_s if timeout is None else timeout
        names = self.select(alert, profile=profile)
        if not names:
            return ("", {}) if return_sections else ""
        pool = self.full_collectors if profile == "full" else self.collectors
        results = {}
        threads = {}
        for n in names:
            fn = pool.get(n)
            if fn is None:
                fn = self.collectors.get(n)  # degrade: no deep variant -> standard closure
            if fn is None:
                continue
            if not self._sem.acquire(blocking=False):
                results[n] = UNAVAIL.format(n)  # pool saturated -> degrade (self-throttle)
                continue

            def run(nn=n, ffn=fn):
                try:
                    results[nn] = ffn(alert, alert_key, now)
                except Exception:
                    results[nn] = UNAVAIL.format(nn)
                finally:
                    self._sem.release()

            t = threading.Thread(target=run, daemon=True)  # daemon: no atexit-join hang
            t.start()
            threads[n] = t

        end = time.monotonic() + max(0.0, timeout)
        for t in threads.values():
            t.join(max(0.0, end - time.monotonic()))
        for n in names:
            results.setdefault(n, UNAVAIL.format(n))  # slow/still-running -> degrade
        bundle = assemble_bundle(results, self.max_bytes)
        if return_sections:
            return bundle, dict(results)
        return bundle
