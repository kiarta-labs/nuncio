"""Redactor fixture suite. Iron rule: zero secrets survive.

Each test asserts (a) the secret value is GONE from the output and (b) a typed
finding is recorded so the LLM still sees a credential *was* present and of what
kind (often diagnostic — e.g. the Vector 401 was an env-var secret problem).
"""
from nuncio.redactor import redact


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
