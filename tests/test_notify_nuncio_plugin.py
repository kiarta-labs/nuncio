"""integrations/checkmk/notify_nuncio.py: the CheckMK notification plugin's
Apprise-direct fallback path. This plugin runs INSIDE CheckMK's own Python
and cannot import the `nuncio` package, so it carries a small self-contained
copy of the unexpanded-macro scrub and severity-emoji mapping. These tests
exercise the plugin's pure helper functions directly (imported by file path,
since `integrations/checkmk/` is not a package on sys.path).
"""
import importlib.util
import json
import os
import pathlib

_PLUGIN_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "integrations" / "checkmk" / "notify_nuncio.py"
)
_spec = importlib.util.spec_from_file_location("notify_nuncio_plugin", _PLUGIN_PATH)
notify_nuncio = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(notify_nuncio)


# --- state_symbol ---

def test_state_symbol_critical_states():
    for state in ("CRITICAL", "CRIT", "DOWN"):
        assert notify_nuncio.state_symbol(state) == "❗"


def test_state_symbol_warning_states():
    for state in ("WARNING", "WARN"):
        assert notify_nuncio.state_symbol(state) == "🟡"


def test_state_symbol_ok_states():
    for state in ("OK", "UP"):
        assert notify_nuncio.state_symbol(state) == "✅"


def test_state_symbol_unknown_states():
    for state in ("UNKNOWN", "UNREACHABLE", "bogus", "", None):
        assert notify_nuncio.state_symbol(state) == "❔"


def test_state_symbol_is_case_insensitive():
    assert notify_nuncio.state_symbol("critical") == "❗"
    assert notify_nuncio.state_symbol("down") == "❗"


# --- macro scrub ---

def test_clean_strips_unexpanded_macro():
    assert notify_nuncio._clean("$SERVICEDESC$") == ""


def test_clean_leaves_real_value_alone():
    assert notify_nuncio._clean("infisical-postgres") == "infisical-postgres"


# --- is_service_notification ---
#
# Phase 1 (production bug #3-residual): classification now requires a REAL
# NOTIFY_SERVICEDESC. NOTIFY_WHAT=="SERVICE" alone (blank/unexpanded
# SERVICEDESC) must no longer manufacture a service notification -- this
# plugin's classification must never disagree with the adapter's
# `nuncio.sources.checkmk._is_service` for the same inputs.

def test_is_service_notification_false_for_service_what_with_no_servicedesc():
    assert notify_nuncio.is_service_notification({"NOTIFY_WHAT": "SERVICE"}) is False


def test_is_service_notification_false_for_service_what_with_unexpanded_servicedesc():
    notification = {"NOTIFY_WHAT": "SERVICE", "NOTIFY_SERVICEDESC": "$SERVICEDESC$"}
    assert notify_nuncio.is_service_notification(notification) is False


def test_is_service_notification_false_for_host_with_unexpanded_macro():
    notification = {"NOTIFY_WHAT": "HOST", "NOTIFY_SERVICEDESC": "$SERVICEDESC$"}
    assert notify_nuncio.is_service_notification(notification) is False


def test_is_service_notification_true_for_real_service_desc():
    notification = {"NOTIFY_WHAT": "HOST", "NOTIFY_SERVICEDESC": "CPU load"}
    assert notify_nuncio.is_service_notification(notification) is True


def test_is_service_notification_true_for_service_what_and_real_servicedesc():
    notification = {"NOTIFY_WHAT": "SERVICE", "NOTIFY_SERVICEDESC": "CPU load"}
    assert notify_nuncio.is_service_notification(notification) is True


# --- adapter/plugin classification parity: same inputs, same verdict ---

def test_plugin_classification_matches_adapter_classification():
    from nuncio.sources.checkmk import _is_service

    matrix = [
        {"NOTIFY_WHAT": "SERVICE"},
        {"NOTIFY_WHAT": "SERVICE", "NOTIFY_SERVICEDESC": "$SERVICEDESC$"},
        {"NOTIFY_WHAT": "SERVICE", "NOTIFY_SERVICEDESC": "CPU load"},
        {"NOTIFY_WHAT": "HOST"},
        {"NOTIFY_WHAT": "HOST", "NOTIFY_SERVICEDESC": "$SERVICEDESC$"},
        {"NOTIFY_WHAT": "HOST", "NOTIFY_SERVICEDESC": "CPU load"},
        {},
    ]
    for notification in matrix:
        assert notify_nuncio.is_service_notification(notification) == _is_service(notification), \
            notification


# --- build_fallback ---

SERVICE_NOTIFICATION = {
    "NOTIFY_WHAT": "SERVICE",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "host01",
    "NOTIFY_SERVICEDESC": "infisical-postgres",
    "NOTIFY_SERVICESTATE": "CRIT",
    "NOTIFY_SERVICEOUTPUT": "FATAL: all AuxiliaryProcs are in use",
}

HOST_NOTIFICATION_UNEXPANDED_MACROS = {
    "NOTIFY_WHAT": "HOST",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "KiritPC",
    "NOTIFY_HOSTSTATE": "DOWN",
    "NOTIFY_HOSTOUTPUT": "CRITICAL - Host unreachable",
    "NOTIFY_SERVICEDESC": "$SERVICEDESC$",
    "NOTIFY_SERVICESTATE": "$SERVICESTATE$",
}


def test_build_fallback_title_for_service_notification():
    title, body, kind = notify_nuncio.build_fallback(SERVICE_NOTIFICATION)
    assert title == "❗ host01 / infisical-postgres — FATAL: all AuxiliaryProcs are in use"
    assert kind == "failure"


def test_build_fallback_title_for_host_notification_with_unexpanded_macros():
    title, body, kind = notify_nuncio.build_fallback(HOST_NOTIFICATION_UNEXPANDED_MACROS)
    # must not be misclassified as a service notification, and must not
    # contain any literal $MACRO$ text
    assert "$" not in title
    assert title == "❗ KiritPC — CRITICAL - Host unreachable"
    assert kind == "failure"


def test_build_fallback_recovery_is_success_kind():
    recovery = dict(SERVICE_NOTIFICATION, NOTIFY_NOTIFICATIONTYPE="RECOVERY",
                     NOTIFY_SERVICESTATE="OK", NOTIFY_SERVICEOUTPUT="all good")
    title, body, kind = notify_nuncio.build_fallback(recovery)
    assert title.startswith("✅")
    assert kind == "success"


def test_build_fallback_body_mentions_notification_type_and_output():
    _, body, _ = notify_nuncio.build_fallback(SERVICE_NOTIFICATION)
    assert "PROBLEM" in body
    assert "FATAL: all AuxiliaryProcs are in use" in body


# --- main() is guarded (importing the module must not perform network I/O) ---

def test_module_has_no_module_level_side_effects():
    # If the plugin still ran its POST logic at import time, exec_module
    # above would have already raised/blocked on a real network call. This
    # asserts the guard function exists and top-level import succeeded cleanly.
    assert callable(notify_nuncio.main)


# --- local spool: CheckMK RAW has no notification spool of its own, so if
# BOTH the Nuncio handoff and the Apprise fallback fail, the alert must be
# durably saved for retry, not dropped. These tests exercise the spool
# read/write/drain helpers directly, then main()'s wiring of them. ---

def _notify_env(monkeypatch, **overrides):
    """Set the minimal NOTIFY_* environment for one notification, clearing
    any stale NOTIFY_ vars left over from a previous test in this process."""
    for k in list(os.environ):
        if k.startswith("NOTIFY_"):
            monkeypatch.delenv(k, raising=False)
    base = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
        "NOTIFY_HOSTNAME": "spool-host",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_HOSTOUTPUT": "CRITICAL - host unreachable",
        "NOTIFY_HOSTPROBLEMID": "99",
        "NOTIFY_NOTIFICATIONNUMBER": "1",
    }
    base.update(overrides)
    for k, v in base.items():
        monkeypatch.setenv(k, v)


class FakeTransport:
    """Stand-in for notify_nuncio.post: routes by URL substring so a single
    fake can independently control the Nuncio and Apprise legs."""

    def __init__(self, nuncio_ok, apprise_ok):
        self.nuncio_ok = nuncio_ok
        self.apprise_ok = apprise_ok
        self.calls = []

    def __call__(self, url, payload, headers, timeout):
        self.calls.append(url)
        if "/ingest/checkmk" in url:
            if self.nuncio_ok:
                return 200
            raise ConnectionError("nuncio down")
        if self.apprise_ok:
            return 200
        raise ConnectionError("apprise down")


# --- spool_write / spool_list ---

def test_spool_write_and_list_round_trip(tmp_path):
    record = {"key_hint": "h", "notification": {"NOTIFY_HOSTNAME": "h"},
              "title": "t", "body": "b", "kind": "failure"}
    assert notify_nuncio.spool_write(str(tmp_path), record) is True
    files = notify_nuncio.spool_list(str(tmp_path))
    assert len(files) == 1
    with open(files[0], encoding="utf-8") as f:
        assert json.load(f) == record


def test_spool_write_uses_atomic_rename_no_leftover_tmp_file(tmp_path):
    record = {"key_hint": "h", "notification": {}, "title": "t", "body": "b", "kind": "info"}
    notify_nuncio.spool_write(str(tmp_path), record)
    names = os.listdir(str(tmp_path))
    assert all(not n.endswith(".tmp") for n in names)


# --- spool_dir ---

def test_spool_dir_uses_override_env(tmp_path, monkeypatch):
    target = str(tmp_path / "spool")
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", target)
    monkeypatch.delenv("OMD_ROOT", raising=False)
    d = notify_nuncio.spool_dir()
    assert d == target
    assert os.path.isdir(d)


def test_spool_dir_uses_omd_root_when_no_override(tmp_path, monkeypatch):
    monkeypatch.delenv("NUNCIO_PLUGIN_SPOOL_DIR", raising=False)
    monkeypatch.setenv("OMD_ROOT", str(tmp_path / "site"))
    d = notify_nuncio.spool_dir()
    assert d == str(tmp_path / "site" / "var" / "tmp" / "nuncio_spool")
    assert os.path.isdir(d)


# --- spool_drain ---

def test_spool_drain_redelivers_to_nuncio_and_deletes_file(tmp_path, monkeypatch):
    record = {"key_hint": "h", "notification": {"NOTIFY_HOSTNAME": "h"},
              "title": "t", "body": "b", "kind": "failure"}
    notify_nuncio.spool_write(str(tmp_path), record)
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=True, apprise_ok=True))
    drained = notify_nuncio.spool_drain(str(tmp_path), "http://nuncio:8095", "",
                                        "http://apprise/notify", timeout=1, limit=10)
    assert drained == 1
    assert notify_nuncio.spool_list(str(tmp_path)) == []


def test_spool_drain_falls_back_to_apprise_when_nuncio_still_down(tmp_path, monkeypatch):
    record = {"key_hint": "h", "notification": {"NOTIFY_HOSTNAME": "h"},
              "title": "t", "body": "b", "kind": "failure"}
    notify_nuncio.spool_write(str(tmp_path), record)
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=True))
    drained = notify_nuncio.spool_drain(str(tmp_path), "http://nuncio:8095", "",
                                        "http://apprise/notify", timeout=1, limit=10)
    assert drained == 1
    assert notify_nuncio.spool_list(str(tmp_path)) == []


def test_spool_drain_leaves_file_when_both_transports_down(tmp_path, monkeypatch):
    record = {"key_hint": "h", "notification": {"NOTIFY_HOSTNAME": "h"},
              "title": "t", "body": "b", "kind": "failure"}
    notify_nuncio.spool_write(str(tmp_path), record)
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=False))
    drained = notify_nuncio.spool_drain(str(tmp_path), "http://nuncio:8095", "",
                                        "http://apprise/notify", timeout=1, limit=10)
    assert drained == 0
    assert len(notify_nuncio.spool_list(str(tmp_path))) == 1


def test_spool_drain_is_bounded_by_limit(tmp_path, monkeypatch):
    for i in range(5):
        notify_nuncio.spool_write(str(tmp_path), {"key_hint": "h{}".format(i),
                                                   "notification": {}, "title": "t",
                                                   "body": "b", "kind": "info"})
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=True, apprise_ok=True))
    drained = notify_nuncio.spool_drain(str(tmp_path), "http://nuncio:8095", "",
                                        "http://apprise/notify", timeout=1, limit=2)
    assert drained == 2
    assert len(notify_nuncio.spool_list(str(tmp_path))) == 3


# --- main(): end-to-end wiring of drain-first + spool-on-total-failure ---

def test_main_returns_zero_when_nuncio_succeeds_directly(tmp_path, monkeypatch):
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=True, apprise_ok=True))

    assert notify_nuncio.main() == 0
    assert notify_nuncio.spool_list(str(tmp_path)) == []


def test_main_falls_back_to_apprise_when_nuncio_down_without_spooling(tmp_path, monkeypatch):
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=True))

    assert notify_nuncio.main() == 0
    assert notify_nuncio.spool_list(str(tmp_path)) == []


def test_main_spools_when_both_nuncio_and_apprise_down(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=False))

    rc = notify_nuncio.main()

    assert rc == 0  # spooled for retry counts as "not lost"
    files = notify_nuncio.spool_list(str(tmp_path))
    assert len(files) == 1
    with open(files[0], encoding="utf-8") as f:
        record = json.load(f)
    assert record["notification"]["NOTIFY_HOSTNAME"] == "spool-host"
    assert "Spooled" in capsys.readouterr().out


def test_main_warns_loudly_when_fallback_url_unset(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    _notify_env(monkeypatch)
    monkeypatch.delenv("NOTIFY_PARAMETER_3", raising=False)
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=False))

    rc = notify_nuncio.main()

    out = capsys.readouterr().out
    assert "WARNING" in out
    assert rc == 0  # still spooled -- not lost
    assert len(notify_nuncio.spool_list(str(tmp_path))) == 1


def test_main_drains_stuck_spool_entry_before_processing_new_notification(tmp_path, monkeypatch):
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    stuck = {"key_hint": "old", "notification": {"NOTIFY_HOSTNAME": "old-host"},
             "title": "old", "body": "old", "kind": "failure"}
    notify_nuncio.spool_write(str(tmp_path), stuck)
    assert len(notify_nuncio.spool_list(str(tmp_path))) == 1

    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=True, apprise_ok=True))

    assert notify_nuncio.main() == 0
    # transport was restored -- the previously-stuck alert must have drained
    assert notify_nuncio.spool_list(str(tmp_path)) == []


def test_main_returns_one_when_delivery_and_spool_both_fail(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(blocker / "sub"))
    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=False))

    assert notify_nuncio.main() == 1


def test_main_build_fallback_exception_still_reaches_spool(tmp_path, monkeypatch):
    # build_fallback raising must not escape main() and skip the spool path.
    monkeypatch.setenv("NUNCIO_PLUGIN_SPOOL_DIR", str(tmp_path))
    _notify_env(monkeypatch)
    monkeypatch.setenv("NOTIFY_PARAMETER_3", "http://apprise:8000/notify/checkmk")
    monkeypatch.setattr(notify_nuncio, "post", FakeTransport(nuncio_ok=False, apprise_ok=False))
    monkeypatch.setattr(notify_nuncio, "build_fallback",
                         lambda notification: (_ for _ in ()).throw(RuntimeError("boom")))

    rc = notify_nuncio.main()

    assert rc == 0
    assert len(notify_nuncio.spool_list(str(tmp_path))) == 1
