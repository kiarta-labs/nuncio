"""Deadline manager.

The hard end-to-end budget starts at INGEST and counts queue-wait. When it
expires, the raw alert ships regardless of pipeline state. Clock is injected so
tests are deterministic (no real sleeping).
"""
import time

import pytest

from nuncio.deadline import Deadline, run_bounded


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def test_fresh_deadline_not_expired():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    assert not d.expired()
    assert d.remaining() == 45.0
    assert d.elapsed() == 0.0


def test_remaining_decreases_as_time_passes():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    clk.advance(10.0)
    assert d.elapsed() == 10.0
    assert d.remaining() == 35.0
    assert not d.expired()


def test_expires_exactly_at_budget():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    clk.advance(45.0)
    assert d.remaining() == 0.0
    assert d.expired()


def test_remaining_floors_at_zero_after_budget():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    clk.advance(100.0)
    assert d.remaining() == 0.0
    assert d.expired()


def test_can_afford_attempt_true_when_enough_budget():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    # need 23s (per-attempt 20 + delivery 3); 45 remaining -> yes
    assert d.can_afford(23.0) is True


def test_can_afford_attempt_false_when_insufficient():
    clk = FakeClock()
    d = Deadline(45.0, clock=clk)
    clk.advance(32.0)  # 13s remaining
    assert d.can_afford(23.0) is False


# --- run_bounded: the shared hard-abandon-the-thread pattern ---

def test_run_bounded_returns_value_on_fast_success():
    assert run_bounded(lambda: 42, 5.0) == 42


def test_run_bounded_reraises_the_original_exception():
    def boom():
        raise ValueError("nope")
    with pytest.raises(ValueError, match="nope"):
        run_bounded(boom, 5.0)


def test_run_bounded_raises_timeout_error_on_hang():
    def hang():
        time.sleep(1.0)
        return "late"
    with pytest.raises(TimeoutError):
        run_bounded(hang, 0.05)
