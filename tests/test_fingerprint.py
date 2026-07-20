"""nuncio/fingerprint.py: recurrence fingerprinting is pure, deterministic,
and never raises. Never suppresses -- see the module docstring."""
from nuncio.fingerprint import fingerprint, signature
from nuncio.store import Store


class FakeWall:
    def __init__(self, t=1000.0): self.t = t
    def __call__(self): return self.t


# --- signature() normalization ---

def test_signature_strips_iso_timestamp():
    sig = signature({"output": "failed at 2026-07-17T10:22:31Z", "state": "CRIT"})
    assert "2026-07-17" not in sig
    assert "<ts>" in sig


def test_signature_strips_uuid():
    sig = signature({"output": "job 550e8400-e29b-41d4-a716-446655440000 failed"})
    assert "550e8400" not in sig
    assert "<uuid>" in sig


def test_signature_strips_hex_runs():
    sig = signature({"output": "GPF at address 0xdeadbeefcafe"})
    assert "deadbeefcafe" not in sig
    assert "<hex>" in sig


def test_signature_collapses_digit_runs():
    sig = signature({"output": "restart count 42 exceeded 10 limit"})
    assert "42" not in sig
    assert "10" not in sig
    assert "<n>" in sig


def test_signature_lowercases_and_collapses_whitespace():
    sig = signature({"output": "FATAL   Error\n\nHappened", "state": "CRIT"})
    assert sig == sig.lower()
    assert "  " not in sig


def test_signature_capped_at_200_chars():
    sig = signature({"output": "x" * 500})
    assert len(sig) <= 200


def test_signature_never_raises_on_garbage():
    assert signature(None) == ""
    assert signature({}) == ""
    assert signature({"output": None, "state": None}) == ""
    assert signature("not a dict") == ""


# --- fingerprint() ---

def test_two_gpf_storms_with_different_addresses_same_fingerprint():
    a = {"source": "checkmk", "host": "host01",
         "output": "general protection fault at address 0xdeadbeef0001", "state": "CRIT"}
    b = {"source": "checkmk", "host": "host01",
         "output": "general protection fault at address 0xcafebabe9999", "state": "CRIT"}
    assert fingerprint(a) == fingerprint(b)


def test_different_service_different_fingerprint():
    a = {"source": "checkmk", "host": "host01", "output": "container down", "state": "CRIT"}
    b = {"source": "checkmk", "host": "host02", "output": "container down", "state": "CRIT"}
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_is_16_hex_chars():
    fp = fingerprint({"source": "checkmk", "host": "h", "output": "boom", "state": "CRIT"})
    assert len(fp) == 16
    int(fp, 16)  # valid hex


def test_fingerprint_none_when_signature_empty():
    assert fingerprint({"source": "checkmk", "host": "h", "output": "", "state": ""}) is None
    assert fingerprint(None) is None


def test_fingerprint_never_raises_on_garbage():
    assert fingerprint("not a dict") is None
    assert fingerprint({"output": object()}) is None or isinstance(fingerprint({"output": object()}), str)


def test_fingerprint_deterministic():
    alert = {"source": "checkmk", "host": "host01", "output": "wedge detected", "state": "CRIT"}
    assert fingerprint(alert) == fingerprint(dict(alert))


# --- store integration: fingerprint_stats ---

def test_fingerprint_stats_count_and_first_seen():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    alert = {"source": "checkmk", "host": "host01", "output": "wedge detected 1234", "state": "CRIT"}
    fp = fingerprint(alert)
    wall.t = 800.0; s.persist("k1", "p", fingerprint=fp)
    wall.t = 900.0; s.persist("k2", "p", fingerprint=fp)
    count, first_seen = s.fingerprint_stats(fp, window_s=86400, now=1000.0)
    assert count == 2
    assert first_seen == 800.0
    s.close()


def test_fingerprint_stats_respects_window():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 100.0; s.persist("old", "p", fingerprint="fp1")  # outside window
    wall.t = 990.0; s.persist("new", "p", fingerprint="fp1")
    count, _ = s.fingerprint_stats("fp1", window_s=100, now=1000.0)
    assert count == 1  # only "new" is within [900, 1000]
    s.close()


def test_fingerprint_stats_canary_excluded():
    wall = FakeWall(1000.0)
    s = Store(":memory:", clock=wall)
    wall.t = 990.0; s.persist("canary:hb", "p", fingerprint="fp1")
    count, _ = s.fingerprint_stats("fp1", window_s=100, now=1000.0)
    assert count == 0
    s.close()


# --- migration idempotence: opening a pre-0.3 DB twice never errors ---

def test_migration_idempotent_on_repeated_open(tmp_path):
    path = str(tmp_path / "premigration.db")
    s1 = Store(path)
    s1.persist("k1", "p")
    s1.close()
    # Re-open twice more -- the ALTER TABLE ADD COLUMN loop is PRAGMA-guarded,
    # so this must never raise "duplicate column name".
    s2 = Store(path)
    s2.close()
    s3 = Store(path)
    row = s3.get_alert_detail("k1")
    assert row["fingerprint"] is None
    s3.close()
