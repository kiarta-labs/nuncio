"""Redactor fixture suite. Iron rule: zero secrets survive.

Each test asserts (a) the secret value is GONE from the output and (b) a typed
finding is recorded so the LLM still sees a credential *was* present and of what
kind (often diagnostic — e.g. the Vector 401 was an env-var secret problem).
"""
from nuncio.redactor import (
    compile_allow_keywords,
    count_redactions,
    get_allow_keywords,
    redact,
    scrub_for_assist_plane,
    scrub_for_knowledge_plane,
    set_allow_keywords,
)


def test_redacts_jwt():
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.abc-DEF_123signature"
    text = f"auth failed for token {secret} on host host01"
    out, findings = redact(text)
    assert secret not in out
    assert "«REDACTED:jwt»" in out
    assert any(f["type"] == "jwt" for f in findings)
    assert "host host01" in out  # non-secret context preserved


def test_redacts_openai_style_key():
    secret = "sk-" "abcDEF1234567890abcDEF1234567890abcDEF12"
    out, findings = redact(f"LITELLM_MASTER_KEY={secret}")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)


def test_redacts_github_token():
    secret = "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    out, findings = redact(f"remote uses {secret} to push")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)


def test_redacts_aws_access_key():
    secret = "AKIAIOSFODNN7EXAMPLE"
    out, findings = redact(f"aws creds {secret} rejected")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)


def test_redacts_kv_password():
    out, findings = redact("db connect: password=Sup3rS3cret! host=paperless-db")
    assert "Sup3rS3cret!" not in out
    assert any(f["type"] == "kv_secret" for f in findings)
    assert "paperless-db" in out  # non-secret KV preserved


def test_redacts_basic_auth_in_url():
    out, findings = redact("cloning https://user:hunter2@git.example.net/repo.git")
    assert "hunter2" not in out
    assert any(f["type"] == "basic_auth" for f in findings)
    assert "git.example.net" in out  # host preserved, only creds stripped


def test_redacts_private_key_block():
    block = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
             "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==\n"
             "-----END OPENSSH PRIVATE KEY-----")
    out, findings = redact(f"key leaked in log:\n{block}\nend")
    assert "b3BlbnNzaC1rZXktdjEA" not in out
    assert any(f["type"] == "private_key" for f in findings)


def test_redacts_authorization_header():
    out, findings = redact("GET /api\r\nAuthorization: Bearer topsecrettoken123\r\nHost: x")
    assert "topsecrettoken123" not in out
    assert any(f["type"] == "auth_header" for f in findings)


def test_redacts_env_var_value_by_name_keeps_name():
    # The Vector 401 case: a secret-bearing env line quoted in a log/config.
    out, findings = redact("VECTOR_O2_PASSWORD=s3cr3tvalue in the failing config")
    assert "s3cr3tvalue" not in out
    assert "VECTOR_O2_PASSWORD=" in out  # NAME kept (diagnostic), value gone
    assert "REDACTED" in out
    assert findings  # something was redacted


def test_non_secret_text_unchanged_no_findings():
    text = "CIFS mount race on host host01 for //fileserver/media at boot; container sonarr affected"
    out, findings = redact(text)
    assert out == text
    assert findings == []


def test_redact_returns_findings_with_count_never_the_value():
    secret = "sk-" "abcDEF1234567890abcDEF1234567890abcDEF12"
    _, findings = redact(f"key {secret}")
    # findings carry type + count, NEVER the secret value (audit-safe logging).
    for f in findings:
        assert secret not in str(f)
        assert "type" in f and "count" in f


# --- Hardening pass: broader token catalog + separators/headers ---
# Added after research confirmed regex-primary is correct but the catalog was thin.

def test_redacts_google_api_key():
    secret = "AIza" "SyD-1234567890abcdefghijklmnopqrstuv"
    out, findings = redact(f"maps call failed with key {secret}")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)


def test_redacts_gateway_token_shape():
    # A common hosted-LLM-gateway token shape (AQ.<b64url...>).
    secret = "AQ." "Ab8RN6Jc1234567890abcdefghijklmnopqrst"
    out, findings = redact(f"request used {secret} downstream")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)


def test_redacts_github_family():
    for secret in ("gho_" "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                   "github_pat_" "11ABCDE0123456789_abcdefghijklmnopqrstuvwxyz"):
        out, findings = redact(f"token {secret} used")
        assert secret not in out, secret
        assert any(f["type"] == "api_key" for f in findings)


def test_redacts_slack_and_stripe():
    for secret in ("xoxb-" "1234567890-1234567890123-abcdEFGHijklMNOPqrstUVwx",
                   "sk_live_" "1234567890abcdefghijklmnop"):
        out, findings = redact(f"webhook auth {secret}")
        assert secret not in out, secret
        assert any(f["type"] == "api_key" for f in findings)


def test_redacts_x_api_key_header():
    out, findings = redact("POST /v1\r\nX-Api-Key: mysupersecretapikeyvalue123\r\nHost: x")
    assert "mysupersecretapikeyvalue123" not in out
    assert any(f["type"] == "auth_header" for f in findings)


def test_redacts_json_password_field():
    out, findings = redact('config: {"host": "paperless-db", "password": "Sup3rS3cret!"}')
    assert "Sup3rS3cret!" not in out
    assert any(f["type"] == "kv_secret" for f in findings)
    assert "paperless-db" in out


def test_redacts_yaml_token_field():
    out, findings = redact("gatus:\n  token: abc123secrettoken\n  interval: 30s")
    assert "abc123secrettoken" not in out
    assert any(f["type"] == "kv_secret" for f in findings)
    assert "interval: 30s" in out


# --- denylist gaps: secrets that a naive PASSWORD-only rule would miss ---

def test_redacts_smb_pass_env_name():
    # SMB_PASS matches no keyword without 'PASS' in the denylist -> real leak.
    secret = "Y0UC@nTP@tcHHum@n$$tupiditY"
    out, findings = redact(f"CIFS mount failed: SMB_PASS={secret} for //fileserver/media")
    assert secret not in out
    assert "//fileserver/media" in out  # identifier kept


def test_redacts_auth_pass_and_pgpass():
    for line in ("keepalived auth_pass=someSecretValue123",
                 "env PGPASS=anotherSecret456 set"):
        out, _ = redact(line)
        assert "someSecretValue123" not in out and "anotherSecret456" not in out, line


def test_redacts_multiword_quoted_secret():
    out, _ = redact('config password: "correct horse battery staple" loaded')
    assert "horse battery staple" not in out  # the WHOLE quoted value, not just word 1
    assert "loaded" in out


def test_entropy_backstop_catches_bare_high_entropy_token():
    # a bare secret with no key name and no known prefix (e.g. an echoed password)
    secret = "kJ8vQ2mZ7pX4wR9nL3bT6yD1aF5cH0eG"
    out, findings = redact(f"unexpected token {secret} in stream")
    assert secret not in out


def test_entropy_backstop_does_not_eat_normal_text():
    text = "container paperless-db restart on host host01 at /srv/appdata"
    out, findings = redact(text)
    assert out == text  # ordinary identifiers/paths/words survive


def test_redacts_alg_none_jwt_empty_signature():
    # alg=none tokens have an empty 3rd segment (trailing dot) -> claims leak
    tok = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0."
    out, findings = redact(f"decoded token {tok} accepted")
    assert "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJyb290In0" not in out
    assert any(f["type"] == "jwt" for f in findings)


# --- Entropy-backstop allowlist -----------------------------------------
#
# The allowlist exempts a token from the entropy BACKSTOP ONLY -- it can
# never rescue a token already caught by a named rule (kv_secret, env,
# api_key, ...), which run and insert placeholders before the entropy pass.


def test_allowlist_never_rescues_a_named_rule_secret():
    set_allow_keywords(["PoE", "token"])
    try:
        out, findings = redact("api_token=PoE-abc123DEF456ghi789XYZ")
        assert "«REDACTED" in out
        assert "PoE-abc123DEF456ghi789XYZ" not in out
    finally:
        set_allow_keywords([])


def test_allowlisted_device_name_survives_all_three_planes():
    set_allow_keywords(["USW", "PoE"])
    try:
        text = "switch USW-Pro-Max-48-PoE-Gen2 flapped"
        out, findings = redact(text)
        assert "USW-Pro-Max-48-PoE-Gen2" in out
        entropy_exempt = [f for f in findings if f["type"] == "entropy_exempt"]
        assert entropy_exempt and entropy_exempt[0]["count"] >= 1

        kp_out, _ = scrub_for_knowledge_plane(text)
        assert "USW-Pro-Max-48-PoE-Gen2" in kp_out

        ap = scrub_for_assist_plane(text)
        assert "USW-Pro-Max-48-PoE-Gen2" in ap.text
    finally:
        set_allow_keywords([])


def test_backstop_still_fires_with_empty_allowlist():
    set_allow_keywords([])
    try:
        text = "switch USW-Pro-Max-48-PoE-Gen2 flapped"
        out, findings = redact(text)
        assert "USW-Pro-Max-48-PoE-Gen2" not in out
        assert any(f["type"] == "high_entropy" for f in findings)
    finally:
        set_allow_keywords([])


def test_allowlist_is_segment_anchored_not_substring():
    # SECURITY: a genuine bare secret that merely CONTAINS "U6" as a
    # substring (never as a delimited segment) must still be redacted.
    set_allow_keywords(["U6"])
    try:
        secret = "aU6bC9dE2fG7hK1mN4pQ8rS"  # >=20 chars, 3 classes, high entropy
        out, findings = redact(f"leaked value {secret} in log")
        assert secret not in out
        assert any(f["type"] == "high_entropy" for f in findings)

        # But a token where "U6" IS a delimited segment is exempt.
        exempt = "U6-Enterprise-XG-Gen2-longenough"
        out2, findings2 = redact(f"device {exempt} online")
        assert exempt in out2
    finally:
        set_allow_keywords([])


def test_allowlist_matching_is_case_sensitive():
    set_allow_keywords(["PoE"])
    try:
        # only candidate segment is lowercase "poe" -- must NOT be exempted
        text = "beacon poe-switch-longenough-suffix99 seen"
        out, findings = redact(text)
        assert "poe-switch-longenough-suffix99" not in out
    finally:
        set_allow_keywords([])

    set_allow_keywords(["poe"])
    try:
        # allowlist is lowercase, token segment is "PoE" -- must NOT be exempted
        text = "device PoE-switch-longenough-suffix99 seen"
        out, findings = redact(text)
        assert "PoE-switch-longenough-suffix99" not in out
    finally:
        set_allow_keywords([])


def test_compile_allow_keywords_rejects_bad_input():
    import pytest

    for bad in ("USW", 42, None):
        with pytest.raises(ValueError):
            compile_allow_keywords(bad)
    with pytest.raises(ValueError):
        compile_allow_keywords([""])
    with pytest.raises(ValueError):
        compile_allow_keywords(["a"])  # 1 char, too short
    with pytest.raises(ValueError):
        compile_allow_keywords(["ok"] * 65)  # too many items
    with pytest.raises(ValueError):
        compile_allow_keywords(["x" * 65])  # too long


def test_set_allow_keywords_rebuilds_a_fresh_list_each_time():
    try:
        caller_list = ["A1"]
        set_allow_keywords(caller_list)
        assert get_allow_keywords() == ["A1"]

        set_allow_keywords(["B2"])
        assert get_allow_keywords() == ["B2"]

        # mutating the caller's original list afterward must not leak in
        caller_list.append("C3")
        assert get_allow_keywords() == ["B2"]
    finally:
        set_allow_keywords([])


def test_count_redactions_excludes_entropy_exempt():
    # entropy_exempt records a token SPARED, not removed -- it must not count.
    findings = [
        {"type": "entropy_exempt", "count": 3},
        {"type": "high_entropy", "count": 2},
        {"type": "kv_secret", "count": 1},
    ]
    assert count_redactions(findings) == 3  # 2 + 1; the 3 exemptions excluded
    assert count_redactions([{"type": "entropy_exempt", "count": 5}]) == 0
    assert count_redactions([]) == 0
    assert count_redactions(None) == 0


def test_allowlisted_token_contributes_zero_to_redaction_count():
    set_allow_keywords(["USW", "PoE"])
    try:
        _, findings = redact("USW-Pro-Max-48-PoE-Gen2 port down")
        # the exemption is recorded for audit ...
        assert any(f["type"] == "entropy_exempt" for f in findings)
        # ... but the redaction tally that feeds the dashboard stat is zero.
        assert count_redactions(findings) == 0
    finally:
        set_allow_keywords([])


# --- basic_auth bounding + global input cap (redact() runs pre-ACK on every
# ingested alert's raw_text; an unbounded scheme quantifier is O(n^2) on any
# long whitespace-free run with no "://" to anchor on — reachable by benign
# base64/hex log content, not just an attacker) ---------------------------

import time  # noqa: E402


def test_redact_is_fast_on_long_secretless_alnum_text():
    # A long base64-ish line with NO "://" anywhere -- pre-fix this alone
    # drove the unanchored basic_auth scheme quantifier quadratic.
    text = "QWxhZGRpbjpvcGVuc2VzYW1l" * 3334  # ~80,000 chars, no "://"
    start = time.monotonic()
    redact(text)
    assert time.monotonic() - start < 2.0


def test_basic_auth_still_redacted_after_bounding():
    out, findings = redact("https://user:hunter2@git.example.net/repo.git")
    assert "hunter2" not in out
    assert any(f["type"] == "basic_auth" for f in findings)

    out, findings = redact("ftp://anon:s3cr3t@files.example.net/x")
    assert "s3cr3t" not in out
    assert any(f["type"] == "basic_auth" for f in findings)

    out, findings = redact("x-my-custom-scheme://u:p@h")
    assert "u:p@h" not in out
    assert any(f["type"] == "basic_auth" for f in findings)


def test_redact_caps_input_length():
    from nuncio.redactor import _INPUT_CAP

    text = "a" * (_INPUT_CAP + 10_000)
    out, findings = redact(text)
    assert len(out) < _INPUT_CAP + 100
    assert any(f["type"] == "input_truncated" for f in findings)


def test_input_truncated_not_counted_as_redaction():
    from nuncio.redactor import _INPUT_CAP

    text = "a" * (_INPUT_CAP + 10_000)
    _, findings = redact(text)
    assert count_redactions(findings) == 0


def test_secret_before_cap_still_redacted_after_truncation():
    from nuncio.redactor import _INPUT_CAP

    secret = "Sup3rS3cret!"
    prefix = "x" * 1000
    text = f"{prefix} password={secret} " + ("a" * _INPUT_CAP)
    out, findings = redact(text)
    assert secret not in out
    assert any(f["type"] == "kv_secret" for f in findings)
