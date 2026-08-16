"""Sliding-window circuit breaker for the private-plane LLM funnel.

Trips when `fails` retryable LLM failures (5xx / 429 / transport) accumulate
within `window_s`; once open, every further call fails fast (the caller falls
back to raw delivery) until `cooldown_s` elapses, at which point a SINGLE
half-open probe call is allowed -- success closes the circuit, failure re-opens
it for another cooldown.

Deliberate scope: hard timeouts are NOT counted (they are ambiguous -- the
request may have succeeded server-side), and non-retryable errors are NOT
counted (4xx is a client/contract bug that retrying cannot fix; tripping on it
would only add noise). The caller decides which failures are retryable and
routes them here via `record_failure`.

Thread-safe (all state under one lock) and clock-injectable for deterministic
tests. `fails <= 0` disables the breaker entirely (every call allowed).
"""
import threading
import time


class CircuitBreaker:
    def __init__(self, fails=3, window_s=300, cooldown_s=60, clock=time.monotonic):
        self.fails = fails
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = []
        self._state = "closed"  # "closed" | "open" | "half_open"
        self._opened_at = None
        self._probe_in_flight = False
        # Lifetime count of transitions into the open state (threshold trip +
        # half-open probe failures). Monotonic per breaker instance; reset by
        # `reconfigure`. Exposed to the metrics renderer as
        # `nuncio_llm_breaker_trips_total`.
        self.trips = 0

    # --- introspection -------------------------------------------------------

    @property
    def state(self):
        with self._lock:
            if self._state == "open" and self._clock() >= self._opened_at + self.cooldown_s:
                self._state = "half_open"
            return self._state

    @property
    def failure_count(self):
        with self._lock:
            return len(self._failures)

    def cooldown_left(self):
        """Seconds until the circuit may leave the open state (0 when not
        open, or already past the cooldown)."""
        with self._lock:
            if self._opened_at is None:
                return 0.0
            return max(0.0, self._opened_at + self.cooldown_s - self._clock())

    # --- call-path hooks -----------------------------------------------------

    def allow(self):
        """True when a call may proceed. In the open state, transitions to
        half-open once the cooldown has elapsed and admits exactly ONE probe
        call; concurrent callers in half-open fail fast."""
        with self._lock:
            now = self._clock()
            if self._state == "closed":
                return True
            if self._state == "open":
                if now < self._opened_at + self.cooldown_s:
                    return False
                self._state = "half_open"
            # half_open: exactly one probe at a time
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    def record_success(self):
        with self._lock:
            if self._state == "half_open":
                self._state = "closed"
                self._probe_in_flight = False
            self._failures = []

    def record_failure(self):
        with self._lock:
            if self.fails <= 0:
                return
            if self._state == "half_open":
                self._state = "open"
                self._opened_at = self._clock()
                self._probe_in_flight = False
                self.trips += 1
                return
            if self._state == "open":
                return  # defensive; allow() never admits calls while open
            now = self._clock()
            self._failures = [t for t in self._failures if now - t <= self.window_s]
            self._failures.append(now)
            if len(self._failures) >= self.fails:
                self._state = "open"
                self._opened_at = now
                self.trips += 1

    # --- live reconfiguration (settings screen) ------------------------------

    def reconfigure(self, fails, window_s, cooldown_s):
        with self._lock:
            self.fails = fails
            self.window_s = window_s
            self.cooldown_s = cooldown_s
            self._failures = []
            self._state = "closed"
            self._opened_at = None
            self._probe_in_flight = False
            self.trips = 0