"""CheckMK source adapter: parses the NOTIFY_* contract into a canonical
alert, with an idempotency key of NOTIFY_(HOST|SERVICE)PROBLEMID. Keys carry
a "checkmk:" source prefix so they can never collide with another source's
keys."""
from nuncio.model import ParsedAlert
from nuncio.sources.checkmk import CheckMK, derive_key, parse_notification

# NOTIFY_NOTIFICATIONNUMBER is a standard CheckMK macro sent on every real
# notification, so "normal case" fixtures below carry it explicitly (the
# absent-number case is exercised separately, further down).
SERVICE_NOTIFY = {
    "NOTIFY_WHAT": "SERVICE",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "host01",
    "NOTIFY_SERVICEDESC": "infisical-postgres",
    "NOTIFY_SERVICESTATE": "CRIT",
    "NOTIFY_SERVICEOUTPUT": "FATAL: all AuxiliaryProcs are in use",
    "NOTIFY_SERVICEPROBLEMID": "12345",
    "NOTIFY_HOSTPROBLEMID": "0",
    "NOTIFY_NOTIFICATIONNUMBER": "1",
    "NOTIFY_SHORTDATETIME": "2026-07-17 09:00:00",
}

HOST_NOTIFY = {
    "NOTIFY_WHAT": "HOST",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "kprintr",
    "NOTIFY_HOSTSTATE": "DOWN",
    "NOTIFY_HOSTOUTPUT": "CRITICAL - host unreachable",
    "NOTIFY_HOSTPROBLEMID": "777",
    "NOTIFY_NOTIFICATIONNUMBER": "1",
    "NOTIFY_SHORTDATETIME": "2026-07-17 09:05:00",
}

# A real-world case: CheckMK sends a HOST notification but leaves the
# SERVICE macros unexpanded (literal "$SERVICEDESC$" etc.) rather than
# omitting them. These must be treated as absent, not as real values.
HOST_NOTIFY_WITH_UNEXPANDED_SERVICE_MACROS = {
    "NOTIFY_WHAT": "HOST",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "KiritPC",
    "NOTIFY_HOSTSTATE": "DOWN",
    "NOTIFY_HOSTOUTPUT": "CRITICAL - Host unreachable",
    "NOTIFY_HOSTPROBLEMID": "42",
    "NOTIFY_SERVICEDESC": "$SERVICEDESC$",
    "NOTIFY_SERVICESTATE": "$SERVICESTATE$",
    "NOTIFY_SERVICEPROBLEMID": "$SERVICEPROBLEMID$",
    "NOTIFY_NOTIFICATIONNUMBER": "1",
    "NOTIFY_SHORTDATETIME": "2026-07-17 09:05:00",
}


def test_service_key_uses_service_problem_id():
    assert derive_key(SERVICE_NOTIFY) == "checkmk:host01/infisical-postgres/12345/PROBLEM/1"


def test_host_key_uses_host_problem_id():
    assert derive_key(HOST_NOTIFY) == "checkmk:kprintr/-/777/PROBLEM/1"


def test_key_carries_source_prefix():
    # every source's key is prefixed so keys can never
    # collide across sources once multiple sources are live.
    assert derive_key(SERVICE_NOTIFY).startswith("checkmk:")


def test_problem_and_recovery_get_distinct_keys():
    recovery = dict(SERVICE_NOTIFY, NOTIFY_NOTIFICATIONTYPE="RECOVERY")
    assert derive_key(recovery) != derive_key(SERVICE_NOTIFY)


def test_periodic_renotifications_get_distinct_keys():
    # same problem, later reminder (NOTIFICATIONNUMBER 2) must NOT be deduped
    first = dict(SERVICE_NOTIFY, NOTIFY_NOTIFICATIONNUMBER="1")
    second = dict(SERVICE_NOTIFY, NOTIFY_NOTIFICATIONNUMBER="2")
    assert derive_key(first) != derive_key(second)


def test_parse_service_notification_fields():
    key, alert, raw = parse_notification(SERVICE_NOTIFY)
    assert alert["host"] == "host01"
    assert alert["service"] == "infisical-postgres"
    assert alert["state"] == "CRIT"
    assert alert["output"] == "FATAL: all AuxiliaryProcs are in use"
    assert alert["timestamp"] == "2026-07-17 09:00:00"
    assert alert["severity"] == "critical"
    assert alert["source"] == "checkmk"


def test_parse_host_notification_uses_host_fields():
    key, alert, raw = parse_notification(HOST_NOTIFY)
    assert alert["host"] == "kprintr"
    assert alert.get("service") in (None, "")
    assert alert["state"] == "DOWN"
    assert alert["output"] == "CRITICAL - host unreachable"
    assert alert["severity"] == "critical"


def test_raw_text_contains_key_fields():
    _, _, raw = parse_notification(SERVICE_NOTIFY)
    for v in ("host01", "infisical-postgres", "FATAL: all AuxiliaryProcs are in use"):
        assert v in raw


def test_raw_text_is_severity_led_for_service_notification():
    # CRIT -> critical -> the "❗" symbol, entity is "host/service"
    _, _, raw = parse_notification(SERVICE_NOTIFY)
    assert raw == "❗ host01/infisical-postgres — FATAL: all AuxiliaryProcs are in use"


def test_raw_text_is_severity_led_for_host_notification():
    _, _, raw = parse_notification(HOST_NOTIFY)
    assert raw == "❗ kprintr — CRITICAL - host unreachable"


def test_raw_text_uses_ok_symbol_for_recovery():
    recovery = dict(HOST_NOTIFY, NOTIFY_NOTIFICATIONTYPE="RECOVERY", NOTIFY_HOSTSTATE="UP",
                     NOTIFY_HOSTOUTPUT="OK - up")
    _, _, raw = parse_notification(recovery)
    assert raw.startswith("✅ kprintr — ")


def test_raw_text_no_bracket_or_state_prefix():
    _, _, raw = parse_notification(SERVICE_NOTIFY)
    assert "[PROBLEM]" not in raw
    assert "CRIT:" not in raw


def test_parse_returns_key_matching_derive_key():
    key, _, _ = parse_notification(SERVICE_NOTIFY)
    assert key == derive_key(SERVICE_NOTIFY)


# --- unexpanded CheckMK macros must be treated as absent (real production bug) ---

def test_is_service_false_for_host_notification_with_unexpanded_service_macro():
    from nuncio.sources.checkmk import _is_service
    assert _is_service(HOST_NOTIFY_WITH_UNEXPANDED_SERVICE_MACROS) is False


def test_host_down_with_unexpanded_macros_parses_as_host_alert():
    _, alert, _ = parse_notification(HOST_NOTIFY_WITH_UNEXPANDED_SERVICE_MACROS)
    assert "service" not in alert
    assert alert["state"] == "DOWN"
    assert alert["severity"] == "critical"
    assert alert["output"] == "CRITICAL - Host unreachable"


def test_host_recovery_with_unexpanded_macros_has_ok_severity():
    recovery = dict(HOST_NOTIFY_WITH_UNEXPANDED_SERVICE_MACROS,
                     NOTIFY_NOTIFICATIONTYPE="RECOVERY", NOTIFY_HOSTSTATE="UP")
    _, alert, _ = parse_notification(recovery)
    assert alert["severity"] == "ok"


def test_derive_key_for_host_with_unexpanded_macros_has_no_dollar_signs():
    key = derive_key(HOST_NOTIFY_WITH_UNEXPANDED_SERVICE_MACROS)
    assert "$" not in key
    assert key == "checkmk:KiritPC/-/42/PROBLEM/1"


# --- the SourceAdapter interface itself ---

def test_adapter_name_is_checkmk():
    assert CheckMK.name == "checkmk"


def test_adapter_parse_returns_one_parsed_alert():
    out = CheckMK().parse(SERVICE_NOTIFY, headers={})
    assert len(out) == 1
    assert isinstance(out[0], ParsedAlert)
    assert out[0].key == "checkmk:host01/infisical-postgres/12345/PROBLEM/1"
    assert out[0].alert["host"] == "host01"
    assert "FATAL" in out[0].raw_text


def test_adapter_rejects_non_dict_payload():
    import pytest
    with pytest.raises(ValueError):
        CheckMK().parse([1, 2, 3], headers={})


def test_adapter_is_registered():
    from nuncio import sources
    assert sources.get("checkmk") is not None
    assert "checkmk" in sources.names()


# --- missing problem-id / notification-number must NOT collapse distinct
# incidents onto the same key (true loss via dedup). When the real macro is
# absent, fall back to a CheckMK-provided timestamp (a stable per-notification
# discriminator) instead of a hardcoded constant. ---

def test_distinct_incidents_without_problem_id_get_distinct_keys():
    # Same host, HOST notification, no NOTIFY_HOSTPROBLEMID at all (macro
    # never set) -- two genuinely different incidents, distinguished only by
    # their timestamp.
    base = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
        "NOTIFY_HOSTNAME": "flaky-host",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_HOSTOUTPUT": "CRITICAL - host unreachable",
    }
    first = dict(base, NOTIFY_MICROTIME="1752739200.123456")
    second = dict(base, NOTIFY_MICROTIME="1752739999.654321")
    assert derive_key(first) != derive_key(second)


def test_replayed_notification_without_problem_id_still_dedupes():
    # The exact same notification (identical macros, identical timestamp)
    # posted twice must still collapse to one key -- this is the "same
    # notification retried" case that dedup exists for.
    notify = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
        "NOTIFY_HOSTNAME": "flaky-host",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_HOSTOUTPUT": "CRITICAL - host unreachable",
        "NOTIFY_MICROTIME": "1752739200.123456",
    }
    assert derive_key(dict(notify)) == derive_key(dict(notify))


def test_normal_notification_with_problem_id_key_unchanged():
    # When the real macros ARE present (the normal case), the key must be
    # byte-identical to today's behavior regardless of any time fields also
    # being present.
    notify = dict(SERVICE_NOTIFY, NOTIFY_MICROTIME="1752739200.123456")
    assert derive_key(notify) == "checkmk:host01/infisical-postgres/12345/PROBLEM/1"


def test_missing_problem_id_prefers_microtime_over_shortdatetime():
    notify = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_HOSTNAME": "h",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_NOTIFICATIONNUMBER": "1",
        "NOTIFY_MICROTIME": "111.222",
        "NOTIFY_SHORTDATETIME": "2026-07-17 09:00:00",
    }
    assert derive_key(notify) == "checkmk:h/-/111.222/PROBLEM/1"


def test_missing_problem_id_falls_back_to_shortdatetime_when_no_microtime():
    notify = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_HOSTNAME": "h",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_NOTIFICATIONNUMBER": "1",
        "NOTIFY_SHORTDATETIME": "2026-07-17 09:00:00",
    }
    assert derive_key(notify) == "checkmk:h/-/2026-07-17 09:00:00/PROBLEM/1"


def test_missing_problem_id_falls_back_to_longdatetime_as_last_resort():
    notify = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_HOSTNAME": "h",
        "NOTIFY_HOSTSTATE": "DOWN",
        "NOTIFY_NOTIFICATIONNUMBER": "1",
        "NOTIFY_LONGDATETIME": "Fri Jul 17 09:00:00 IST 2026",
    }
    assert derive_key(notify) == "checkmk:h/-/Fri Jul 17 09:00:00 IST 2026/PROBLEM/1"


def test_missing_problem_id_with_no_time_fields_falls_back_to_constant_zero():
    notify = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_HOSTNAME": "h",
        "NOTIFY_HOSTSTATE": "DOWN",
    }
    assert derive_key(notify) == "checkmk:h/-/0/PROBLEM/1"


def test_missing_notification_number_uses_time_fallback_not_constant_one():
    notify = dict(SERVICE_NOTIFY)
    del notify["NOTIFY_NOTIFICATIONNUMBER"]  # exercise the number-specific fallback
    notify["NOTIFY_MICROTIME"] = "999.111"
    del notify["NOTIFY_SHORTDATETIME"]
    key = derive_key(notify)
    # pid stays "12345" (still present); only the number falls back to time.
    assert key == "checkmk:host01/infisical-postgres/12345/PROBLEM/999.111"


def test_two_distinct_incidents_no_problem_id_no_number_get_distinct_keys_via_engine_replay_semantics():
    # Belt-and-suspenders: this is the scenario from the bug report -- both
    # problem-id AND notification-number absent, two different incidents.
    base = {
        "NOTIFY_WHAT": "HOST",
        "NOTIFY_HOSTNAME": "flaky-host",
        "NOTIFY_HOSTSTATE": "DOWN",
    }
    first = dict(base, NOTIFY_MICROTIME="1752739200.0")
    second = dict(base, NOTIFY_MICROTIME="1752739999.0")
    assert derive_key(first) != derive_key(second)


# --- Phase 1: canonical extra-field fold-in from CheckMK's rich macros ---

RICH_SERVICE_NOTIFY = dict(
    SERVICE_NOTIFY,
    NOTIFY_LONGSERVICEOUTPUT="line one\\nline two\\tindented",
    NOTIFY_SERVICEPERFDATA="load=5.2;3;4;0;8",
    NOTIFY_SERVICECHECKCOMMAND="check_load!3!4",
    NOTIFY_SERVICEACKAUTHOR="alice",
    NOTIFY_SERVICEACKCOMMENT="looking into it",
    NOTIFY_NOTIFICATIONCOMMENT="please ack",
    NOTIFY_SERVICEDOWNTIME="1",
    NOTIFY_SERVICEGROUPNAMES="dbs",
    NOTIFY_HOSTGROUPNAMES="linux",
    NOTIFY_HOSTTAGS="prod cmk-agent",
    NOTIFY_HOSTADDRESS="10.1.2.3",
    NOTIFY_HOSTALIAS="host01-alias",
    NOTIFY_SERVICEPROBLEMID="12345",
    NOTIFY_NOTIFICATIONNUMBER="3",
)

RICH_HOST_NOTIFY = dict(
    HOST_NOTIFY,
    NOTIFY_LONGHOSTOUTPUT="host line one\\nhost line two",
    NOTIFY_HOSTPERFDATA="rta=1.2ms;100;500;0",
    NOTIFY_HOSTCHECKCOMMAND="check-host-alive",
    NOTIFY_HOSTACKAUTHOR="bob",
    NOTIFY_HOSTACKCOMMENT="on it",
    NOTIFY_HOSTDOWNTIME="1",
    NOTIFY_HOSTGROUPNAMES="printers",
    NOTIFY_HOSTTAGS="lab",
    NOTIFY_HOSTADDRESS="10.4.5.6",
    NOTIFY_HOSTALIAS="kprintr-alias",
    NOTIFY_HOSTPROBLEMID="777",
    NOTIFY_NOTIFICATIONNUMBER="3",
)


def test_service_notification_populates_all_canonical_extras():
    _, alert, _ = parse_notification(RICH_SERVICE_NOTIFY)
    assert alert["details"] == "line one\nline two\tindented"
    assert alert["perfdata"] == "load=5.2;3;4;0;8"
    assert alert["check_command"] == "check_load!3!4"
    assert alert["event"] == "PROBLEM"
    assert alert["ack"] == "alice: looking into it; please ack"
    assert alert["downtime"] == "in scheduled downtime"
    assert alert["groups"] == "dbs; linux; prod cmk-agent"
    assert alert["address"] == "10.1.2.3 (host01-alias)"
    assert alert["recurrence"] == "notification #3 of problem 12345"


def test_service_extras_are_rendered_in_the_prompt():
    from nuncio.prompt import build_level_a_messages
    _, alert, _ = parse_notification(RICH_SERVICE_NOTIFY)
    messages = build_level_a_messages(alert)
    user = messages[1]["content"]
    assert "details: line one\nline two\tindented" in user
    assert "perfdata: load=5.2;3;4;0;8" in user
    assert "check: check_load!3!4" in user
    assert "event: PROBLEM" in user
    assert "ack: alice: looking into it; please ack" in user
    assert "downtime: in scheduled downtime" in user
    assert "groups: dbs; linux; prod cmk-agent" in user
    assert "address: 10.1.2.3 (host01-alias)" in user
    assert "recurrence: notification #3 of problem 12345" in user


def test_host_notification_uses_host_macros_and_omits_service_only_keys():
    _, alert, _ = parse_notification(RICH_HOST_NOTIFY)
    assert alert["details"] == "host line one\nhost line two"
    assert alert["perfdata"] == "rta=1.2ms;100;500;0"
    assert alert["check_command"] == "check-host-alive"
    assert alert["ack"] == "bob: on it"
    assert alert["downtime"] == "in scheduled downtime"
    assert alert["groups"] == "printers; lab"
    assert alert["address"] == "10.4.5.6 (kprintr-alias)"
    assert alert["recurrence"] == "notification #3 of problem 777"


def test_newline_and_tab_unescape_in_details():
    notify = dict(SERVICE_NOTIFY, NOTIFY_LONGSERVICEOUTPUT="a\\nb\\tc")
    _, alert, _ = parse_notification(notify)
    assert alert["details"] == "a\nb\tc"


def test_windows_path_backslashes_survive_unescape_alongside_a_real_newline():
    # M1: a Windows host's CheckMK long output can legitimately contain a
    # path like D:\network\tools. CheckMK escapes a REAL backslash as a
    # literal two-char "\\" sequence and a real newline as a literal
    # two-char "\n" sequence -- both arrive in the SAME string here. The old
    # naive .replace("\\n", "\n") blindly matched the "\n" INSIDE the
    # escaped "\\network" (the backslash + the 'n' of "network"), corrupting
    # the path into "D:" + a real newline + "etwork". The fix must convert
    # only the genuine newline separator and leave the path's backslashes
    # as single, literal characters.
    raw = r"line1\nline2 D:\\network\\tools"
    notify = dict(SERVICE_NOTIFY, NOTIFY_LONGSERVICEOUTPUT=raw)
    _, alert, _ = parse_notification(notify)
    assert alert["details"] == "line1\nline2 D:\\network\\tools"
    assert "D:\\network\\tools" in alert["details"]
    assert "D:\netwo" not in alert["details"]  # the old bug's mangled form


def test_unexpanded_perfdata_macro_is_omitted():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEPERFDATA="$SERVICEPERFDATA$")
    _, alert, _ = parse_notification(notify)
    assert "perfdata" not in alert


def test_downtime_zero_is_omitted():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEDOWNTIME="0")
    _, alert, _ = parse_notification(notify)
    assert "downtime" not in alert


def test_downtime_one_is_present():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEDOWNTIME="1")
    _, alert, _ = parse_notification(notify)
    assert alert["downtime"] == "in scheduled downtime"


def test_ack_present_when_author_and_comment_set():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEACKAUTHOR="alice",
                  NOTIFY_SERVICEACKCOMMENT="looking into it")
    _, alert, _ = parse_notification(notify)
    assert alert["ack"] == "alice: looking into it"


def test_ack_omitted_when_all_ack_fields_empty():
    _, alert, _ = parse_notification(SERVICE_NOTIFY)
    assert "ack" not in alert


def test_ack_author_only():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEACKAUTHOR="alice")
    _, alert, _ = parse_notification(notify)
    assert alert["ack"] == "alice"


def test_ack_comment_only():
    notify = dict(SERVICE_NOTIFY, NOTIFY_SERVICEACKCOMMENT="investigating")
    _, alert, _ = parse_notification(notify)
    assert alert["ack"] == "investigating"


def test_recurrence_omitted_for_first_notification():
    notify = dict(SERVICE_NOTIFY, NOTIFY_NOTIFICATIONNUMBER="1")
    _, alert, _ = parse_notification(notify)
    assert "recurrence" not in alert


def test_recurrence_present_for_notification_number_three():
    notify = dict(SERVICE_NOTIFY, NOTIFY_NOTIFICATIONNUMBER="3")
    _, alert, _ = parse_notification(notify)
    assert alert["recurrence"] == "notification #3 of problem 12345"


def test_regression_plain_notification_unaffected_by_new_macro_handling():
    # No new macros present at all -- key, base alert fields, and raw_text
    # must be byte-identical to the pre-Phase-1 behaviour.
    key, alert, raw = parse_notification(SERVICE_NOTIFY)
    assert key == "checkmk:host01/infisical-postgres/12345/PROBLEM/1"
    assert alert == {
        "host": "host01", "state": "CRIT", "severity": "critical",
        "output": "FATAL: all AuxiliaryProcs are in use", "source": "checkmk",
        "service": "infisical-postgres", "timestamp": "2026-07-17 09:00:00",
        "event": "PROBLEM",
    }
    assert raw == "❗ host01/infisical-postgres — FATAL: all AuxiliaryProcs are in use"


def test_host_regression_plain_notification_unaffected():
    key, alert, raw = parse_notification(HOST_NOTIFY)
    assert key == "checkmk:kprintr/-/777/PROBLEM/1"
    assert alert == {
        "host": "kprintr", "state": "DOWN", "severity": "critical",
        "output": "CRITICAL - host unreachable", "source": "checkmk",
        "timestamp": "2026-07-17 09:05:00", "event": "PROBLEM",
    }
    assert raw == "❗ kprintr — CRITICAL - host unreachable"


def test_fingerprint_identical_with_and_without_extra_macros():
    from nuncio.fingerprint import fingerprint
    _, plain_alert, _ = parse_notification(SERVICE_NOTIFY)
    _, rich_alert, _ = parse_notification(RICH_SERVICE_NOTIFY)
    assert fingerprint(plain_alert) == fingerprint(rich_alert)


# --- Phase 1: lifecycle-deterministic severity (fixes #3-residual) ---
#
# `_is_service` now requires a REAL NOTIFY_SERVICEDESC -- NOTIFY_WHAT=="SERVICE"
# alone (with a blank/unexpanded SERVICEDESC) must no longer manufacture a
# "-"/"-" service alert; it falls to the host branch (host identity + host
# state). `_severity_from` is the deterministic ladder: state (if not
# "unknown") wins; else RECOVERY* -> ok; else ACK/DOWNTIME*/FLAPPING* -> info;
# else unknown (existing LLM-infer path).

from nuncio.sources.checkmk import _is_service, _severity_from

# Case C: a HOST recovery with an unexpanded
# NOTIFY_HOSTSTATE macro -- previously "unknown", must now be "ok".
CASE_C_HOST_RECOVERY_UNEXPANDED_STATE = {
    "NOTIFY_WHAT": "HOST",
    "NOTIFY_NOTIFICATIONTYPE": "RECOVERY",
    "NOTIFY_HOSTNAME": "kprintr",
    "NOTIFY_HOSTSTATE": "$HOSTSTATE$",
    "NOTIFY_HOSTOUTPUT": "OK - up",
    "NOTIFY_HOSTPROBLEMID": "777",
    "NOTIFY_NOTIFICATIONNUMBER": "2",
    "NOTIFY_SHORTDATETIME": "2026-07-17 09:10:00",
}

# Case B: NOTIFY_WHAT=SERVICE with every service macro unexpanded, but real
# host macros present -- previously misclassified as a service alert with a
# "-"/"-" identity and "unknown" severity; must now fall to the host branch.
CASE_B_SERVICE_WHAT_ALL_SERVICE_MACROS_UNEXPANDED = {
    "NOTIFY_WHAT": "SERVICE",
    "NOTIFY_NOTIFICATIONTYPE": "PROBLEM",
    "NOTIFY_HOSTNAME": "host01",
    "NOTIFY_HOSTSTATE": "CRIT",
    "NOTIFY_HOSTOUTPUT": "CRITICAL - host degraded",
    "NOTIFY_SERVICEDESC": "$SERVICEDESC$",
    "NOTIFY_SERVICESTATE": "$SERVICESTATE$",
    "NOTIFY_SERVICEOUTPUT": "$SERVICEOUTPUT$",
    "NOTIFY_HOSTPROBLEMID": "55",
    "NOTIFY_NOTIFICATIONNUMBER": "1",
    "NOTIFY_SHORTDATETIME": "2026-07-17 09:15:00",
}

ACKNOWLEDGEMENT_WITH_BLANK_STATE = {
    "NOTIFY_WHAT": "HOST",
    "NOTIFY_NOTIFICATIONTYPE": "ACKNOWLEDGEMENT",
    "NOTIFY_HOSTNAME": "host01",
    "NOTIFY_HOSTSTATE": "-",
    "NOTIFY_HOSTOUTPUT": "acknowledged",
    "NOTIFY_HOSTPROBLEMID": "88",
    "NOTIFY_NOTIFICATIONNUMBER": "1",
}


def test_is_service_false_for_notify_what_service_with_blank_servicedesc():
    # NOTIFY_WHAT=="SERVICE" alone (no real SERVICEDESC at all) must not
    # manufacture a service alert.
    assert _is_service({"NOTIFY_WHAT": "SERVICE"}) is False


def test_is_service_false_for_notify_what_service_with_unexpanded_servicedesc():
    assert _is_service(CASE_B_SERVICE_WHAT_ALL_SERVICE_MACROS_UNEXPANDED) is False


def test_is_service_true_when_real_servicedesc_present_regardless_of_what():
    assert _is_service({"NOTIFY_WHAT": "HOST", "NOTIFY_SERVICEDESC": "CPU load"}) is True


def test_case_c_host_recovery_with_unexpanded_state_is_ok():
    _, alert, _ = parse_notification(CASE_C_HOST_RECOVERY_UNEXPANDED_STATE)
    assert alert["severity"] == "ok"


def test_case_c_key_uses_host_branch():
    key = derive_key(CASE_C_HOST_RECOVERY_UNEXPANDED_STATE)
    assert key == "checkmk:kprintr/-/777/RECOVERY/2"


def test_case_b_falls_to_host_branch_no_service_key():
    _, alert, _ = parse_notification(CASE_B_SERVICE_WHAT_ALL_SERVICE_MACROS_UNEXPANDED)
    assert "service" not in alert


def test_case_b_severity_from_host_state():
    _, alert, _ = parse_notification(CASE_B_SERVICE_WHAT_ALL_SERVICE_MACROS_UNEXPANDED)
    assert alert["severity"] == "critical"
    assert alert["state"] == "CRIT"


def test_case_b_key_uses_host_problem_id_not_dash_dash():
    key = derive_key(CASE_B_SERVICE_WHAT_ALL_SERVICE_MACROS_UNEXPANDED)
    assert key == "checkmk:host01/-/55/PROBLEM/1"


def test_acknowledgement_with_blank_state_is_info():
    _, alert, _ = parse_notification(ACKNOWLEDGEMENT_WITH_BLANK_STATE)
    assert alert["severity"] == "info"


def test_normal_problem_critical_severity_unchanged_by_ladder():
    # Regression pin: when state is a real, recognized value, the ladder's
    # first rung (normalize_severity(state)) is authoritative -- the
    # NOTIFICATIONTYPE branches must never be consulted.
    _, alert, _ = parse_notification(SERVICE_NOTIFY)
    assert alert["severity"] == "critical"


def test_normal_host_down_severity_unchanged_by_ladder():
    _, alert, _ = parse_notification(HOST_NOTIFY)
    assert alert["severity"] == "critical"


# --- _severity_from: direct unit tests on the ladder itself ---

def test_severity_from_uses_state_when_not_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "PROBLEM"}, "CRIT") == "critical"


def test_severity_from_recovery_type_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "RECOVERY"}, "-") == "ok"


def test_severity_from_recovery_type_prefix_match():
    # NOTIFICATIONTYPE can be "RECOVERY" with no suffix in practice, but the
    # ladder is a startswith() match per the plan -- pin that contract.
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "RECOVERY"}, "") == "ok"


def test_severity_from_acknowledgement_type_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "ACKNOWLEDGEMENT"}, "-") == "info"


def test_severity_from_downtime_start_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "DOWNTIMESTART"}, "-") == "info"


def test_severity_from_downtime_end_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "DOWNTIMEEND"}, "-") == "info"


def test_severity_from_downtime_cancelled_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "DOWNTIMECANCELLED"}, "-") == "info"


def test_severity_from_flapping_start_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "FLAPPINGSTART"}, "-") == "info"


def test_severity_from_flapping_stop_when_state_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "FLAPPINGSTOP"}, "-") == "info"


def test_severity_from_unrecognized_type_when_state_unknown_stays_unknown():
    assert _severity_from({"NOTIFY_NOTIFICATIONTYPE": "PROBLEM"}, "-") == "unknown"


def test_severity_from_missing_notificationtype_when_state_unknown_stays_unknown():
    assert _severity_from({}, "-") == "unknown"


# --- raw_text emoji must use the SAME ladder-derived severity as alert["severity"] ---
#
# Phase 2 carried-over consistency fix: a degenerate RECOVERY with an
# unexpanded HOSTSTATE macro has state == "unknown" but a ladder-derived
# severity of "ok" (test_case_c_host_recovery_with_unexpanded_state_is_ok
# above). Before the fix, raw_text's emoji was derived from a fresh
# normalize_severity(state) call -- "unknown" -> "❔" -- disagreeing with the
# canonical alert["severity"] == "ok" (which renders "✅" everywhere else).

def test_case_c_raw_text_emoji_matches_ladder_severity_not_raw_state():
    _, alert, raw = parse_notification(CASE_C_HOST_RECOVERY_UNEXPANDED_STATE)
    assert alert["severity"] == "ok"
    assert raw.startswith("✅ ")
    assert "❔" not in raw
