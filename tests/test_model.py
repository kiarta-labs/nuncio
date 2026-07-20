"""The canonical alert contract's shared helpers: severity normalization and
the categorize() regex-rule extension point."""
import re

import pytest

from nuncio.model import (
    add_category_rule, canonical_host, categorize, disposition, normalize_severity, real_host,
)


def test_normalize_severity_maps_known_aliases():
    assert normalize_severity("CRIT") == "critical"
    assert normalize_severity("warn") == "warning"
    assert normalize_severity("resolved") == "ok"


def test_normalize_severity_falsy_input_is_unknown():
    assert normalize_severity(None) == "unknown"
    assert normalize_severity("") == "unknown"


def test_normalize_severity_unrecognized_string_is_unknown():
    assert normalize_severity("totally-not-a-real-severity") == "unknown"


# --- disposition: the determinism doctrine's enrichment-framing gate ---

def test_disposition_ok_is_recovery():
    assert disposition("ok") == "recovery"


def test_disposition_info_is_info():
    assert disposition("info") == "info"


def test_disposition_warning_is_problem():
    assert disposition("warning") == "problem"


def test_disposition_critical_is_problem():
    assert disposition("critical") == "problem"


def test_disposition_unknown_is_problem():
    # Conservative default -- an unclassifiable alert is still a genuine
    # problem notification and must get full cause/checks framing, never be
    # silently muted alongside real recoveries/info events.
    assert disposition("unknown") == "problem"


def test_disposition_unrecognized_value_is_problem():
    assert disposition("totally-not-a-real-severity") == "problem"


def test_add_category_rule_rejects_unknown_category():
    with pytest.raises(ValueError, match="unknown category"):
        add_category_rule("not-a-real-category", r"whatever")


def test_add_category_rule_accepts_a_string_pattern_and_extends_categorize():
    add_category_rule("network", r"totally-custom-network-marker-xyz")
    try:
        alert = {"host": "h", "service": "s", "output": "totally-custom-network-marker-xyz seen"}
        assert categorize(alert) == "network"
    finally:
        from nuncio.model import _CATEGORY_RES
        _CATEGORY_RES["network"].pop()


def test_add_category_rule_accepts_a_precompiled_pattern():
    compiled = re.compile(r"another-custom-marker-abc", re.I)
    add_category_rule("hardware", compiled)
    try:
        alert = {"host": "h", "service": "s", "output": "ANOTHER-CUSTOM-MARKER-ABC"}
        assert categorize(alert) == "hardware"
    finally:
        from nuncio.model import _CATEGORY_RES
        _CATEGORY_RES["hardware"].pop()


# --- real_host / canonical_host: the Phase 3 host-identity placeholder
# guard + pure canonicalization (Determinism doctrine: "a placeholder host
# is not a host") ---

def test_real_host_rejects_dash_placeholder():
    assert real_host("-") is None


def test_real_host_rejects_blank_and_none():
    assert real_host("") is None
    assert real_host(None) is None
    assert real_host("   ") is None


def test_real_host_rejects_non_alnum_garbage():
    assert real_host("---") is None
    assert real_host("...") is None


def test_real_host_accepts_a_genuine_host():
    assert real_host("svr") == "svr"
    assert real_host(" svr ") == "svr"
    assert real_host("10.13.37.2") == "10.13.37.2"


def test_canonical_host_none_for_placeholder():
    assert canonical_host("-") is None
    assert canonical_host(None) is None


def test_canonical_host_lowercases():
    assert canonical_host("SVR") == "svr"


def test_canonical_host_strips_one_trailing_dot():
    assert canonical_host("svr.") == "svr"


def test_canonical_host_default_domains_is_exact_match_only():
    # no config -> no suffix stripping -- svr.kirits.net stays as-is
    assert canonical_host("svr.kirits.net") == "svr.kirits.net"
    assert canonical_host("svr.kirits.net") != canonical_host("svr")


def test_canonical_host_strips_configured_suffix():
    assert canonical_host("svr.kirits.net", domains=("kirits.net",)) == "svr"
    assert canonical_host("svr", domains=("kirits.net",)) == "svr"


def test_canonical_host_equivalence_case_and_trailing_dot_and_suffix():
    domains = ("kirits.net",)
    a = canonical_host("svr", domains)
    b = canonical_host("svr.kirits.net", domains)
    c = canonical_host("SVR", domains)
    d = canonical_host("svr.kirits.net.", domains)
    assert a == b == c == d == "svr"


def test_canonical_host_never_strips_to_empty():
    # the value IS the bare configured suffix -- stripping it would produce
    # "", which would silently defeat real_host's own placeholder guard.
    assert canonical_host("kirits.net", domains=("kirits.net",)) == "kirits.net"


def test_canonical_host_multi_suffix_first_match_wins():
    # "svr.kirits.net" ends with BOTH "net" and "kirits.net" if both were
    # configured -- the first configured entry that matches wins,
    # deterministically, regardless of which is "more specific".
    assert canonical_host("svr.kirits.net", domains=("net", "kirits.net")) == "svr.kirits"
    assert canonical_host("svr.kirits.net", domains=("kirits.net", "net")) == "svr"


def test_canonical_host_domain_entries_are_normalized():
    # leading dots / whitespace / case in the CONFIG entry itself are
    # tolerated too.
    assert canonical_host("svr.kirits.net", domains=(" .Kirits.NET ",)) == "svr"


def test_canonical_host_no_dns_resolution_ip_and_hostname_stay_distinct():
    assert canonical_host("10.13.37.2") != canonical_host("svr")
    assert canonical_host("10.13.37.2", domains=("kirits.net",)) != canonical_host(
        "svr", domains=("kirits.net",))


def test_canonical_host_deterministic():
    assert canonical_host("SVR.kirits.net.", ("kirits.net",)) == canonical_host(
        "SVR.kirits.net.", ("kirits.net",))


# --- module docstring accuracy: extras allowlist (Phase 0) ---

def test_module_source_documents_the_extras_allowlist_accurately():
    """`ParsedAlert`'s alert-dict-fields comment used to claim every extra
    field 'flows into the prompt's ## Alert block' -- false, since the
    prompt only ever emitted 5 hardcoded fields. Now that nuncio.prompt's
    _alert_block enforces a fixed allowlist, the comment must say so
    explicitly, including that non-allowlisted keys are dropped and why."""
    import nuncio.model as model_mod
    with open(model_mod.__file__, encoding="utf-8") as f:
        source = f.read()
    assert "allowlist" in source.lower()
    assert "dropped" in source.lower()
    # the old, now-inaccurate blanket claim must be gone
    assert "extras allowed and\n# ignored downstream — they still flow into the prompt" not in source
