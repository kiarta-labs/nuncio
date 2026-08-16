"""Sliding-window circuit breaker (nuncio.circuit). Clock-injected tests of
the full closed -> open -> half-open -> (closed | open) state machine,
including the window/pruning, disable, reconfigure, and thread-safety
behaviour."""
import threading

import pytest

from nuncio.circuit import CircuitBreaker


class FakeClock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_closed_until_fails_failures_within_window():
    clk = FakeClock()
    cb = CircuitBreaker(fails=3, window_s=300, cooldown_s=60, clock=clk)
    assert cb.allow()
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "closed"
    assert cb.allow()
    cb.record_failure()
    assert cb.state == "open"
    assert not cb.allow()


def test_success_resets_failure_count():
    clk = FakeClock()
    cb = CircuitBreaker(fails=3, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    cb.record_success()
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "closed"  # two fresh failures, not a cumulative three


def test_failures_expire_outside_window():
    clk = FakeClock()
    cb = CircuitBreaker(fails=3, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    clk.advance(301)
    cb.record_failure()  # the old two have expired -> only one counts
    assert cb.state == "closed"


def test_open_rejects_until_cooldown_then_allows_single_probe():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "open"
    assert not cb.allow()
    clk.advance(61)
    assert cb.state == "half_open"
    assert cb.allow()        # the single probe
    assert not cb.allow()    # concurrent caller fails fast while probe in flight


def test_half_open_probe_success_closes():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    clk.advance(61)
    assert cb.allow()
    cb.record_success()
    assert cb.state == "closed"
    assert cb.allow()


def test_half_open_probe_failure_reopens():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    clk.advance(61)
    assert cb.allow()
    cb.record_failure()
    assert cb.state == "open"
    assert not cb.allow()


def test_zero_fails_disables_breaker():
    clk = FakeClock()
    cb = CircuitBreaker(fails=0, window_s=300, cooldown_s=60, clock=clk)
    for _ in range(50):
        cb.record_failure()
    assert cb.state == "closed"
    assert cb.allow()


def test_cooldown_left_reports_remaining_seconds():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    assert cb.cooldown_left() == 0.0
    cb.record_failure()
    cb.record_failure()
    clk.advance(20)
    assert cb.cooldown_left() == pytest.approx(40.0)
    clk.advance(50)
    assert cb.cooldown_left() == pytest.approx(0.0)


def test_reconfigure_resets_state_and_parameters():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    assert cb.state == "open"
    cb.reconfigure(5, 600, 120)
    assert cb.state == "closed"
    assert cb.fails == 5 and cb.window_s == 600 and cb.cooldown_s == 120
    assert cb.allow()


def test_thread_safety_smoke():
    clk = FakeClock()
    cb = CircuitBreaker(fails=50, window_s=300, cooldown_s=60, clock=clk)
    errors = []

    def worker():
        try:
            for _ in range(200):
                if cb.allow():
                    cb.record_success()
                else:
                    cb.record_failure()
        except Exception as e:  # pragma: no cover - failure would surface below
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_trips_counts_threshold_trip():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    assert cb.trips == 0
    cb.record_failure()
    assert cb.state == "open"
    assert cb.trips == 1
    cb.record_failure()  # defensive no-op while open
    assert cb.trips == 1


def test_trips_counts_half_open_reopen():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    clk.advance(61)
    assert cb.allow()  # probe
    cb.record_failure()  # probe failed -> re-opens
    assert cb.state == "open"
    assert cb.trips == 2
    clk.advance(61)
    assert cb.allow()
    cb.record_success()  # probe succeeded -> closes, no new trip
    assert cb.state == "closed"
    assert cb.trips == 2


def test_trips_not_counted_for_success_or_disabled_breaker():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_success()
    cb.record_failure()
    cb.record_success()
    assert cb.trips == 0
    off = CircuitBreaker(fails=0, window_s=300, cooldown_s=60, clock=clk)
    for _ in range(10):
        off.record_failure()
    assert off.trips == 0


def test_reconfigure_resets_trips():
    clk = FakeClock()
    cb = CircuitBreaker(fails=2, window_s=300, cooldown_s=60, clock=clk)
    cb.record_failure()
    cb.record_failure()
    assert cb.trips == 1
    cb.reconfigure(5, 600, 120)
    assert cb.trips == 0