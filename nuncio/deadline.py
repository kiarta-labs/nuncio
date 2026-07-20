"""Deadline manager.

Owns the hard end-to-end budget measured from ingest (including queue-wait).
Clock is injectable so the pipeline's timing is deterministically testable.
"""
import threading
import time


class Deadline:
    def __init__(self, budget_s, clock=time.monotonic):
        self._budget = float(budget_s)
        self._clock = clock
        self._start = clock()

    def elapsed(self):
        return self._clock() - self._start

    def remaining(self):
        return max(0.0, self._budget - self.elapsed())

    def expired(self):
        return self.remaining() <= 0.0

    def can_afford(self, cost_s):
        """True if at least `cost_s` seconds remain (e.g. an LLM attempt +
        delivery budget) — used to gate retries."""
        return self.remaining() >= cost_s


def run_bounded(fn, bound):
    """Run the no-args callable `fn` with a HARD wall-clock bound, so a
    hung/slow-drip network call can never freeze the calling thread past
    `bound` seconds (a socket-level timeout on the transport is per-op, not
    total, so it alone is not enough). On timeout the call is abandoned --
    its thread leaks until its own I/O eventually times out -- and this
    raises `TimeoutError`. Any OTHER exception `fn` raises is re-raised here,
    unchanged, on the caller's thread. A successful call returns `fn()`'s
    return value unchanged.

    One implementation, two callers: `nuncio.engine.Engine._call_bounded`
    (private-plane + knowledge-plane calls, inside the 30s alert deadline)
    and `nuncio.assist.AssistTrack`'s worker (the out-of-band assist call, on
    its own 60s post-delivery budget) -- both need the exact same
    abandon-the-thread pattern, so it lives here once rather than twice."""
    result = {}

    def run():
        try:
            result["ok"] = fn()
        except Exception as e:  # noqa: BLE001 — re-raised on the caller's thread
            result["err"] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(max(0.0, bound))
    if t.is_alive():
        raise TimeoutError("hard timeout")
    if "err" in result:
        raise result["err"]
    return result["ok"]
