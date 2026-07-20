"""Knowledge-plane (hosted-endpoint) scrubber — verifies IPs and FQDNs are
stripped before anything reaches an external LLM endpoint, while bare
hostnames are allowed through.

Policy: bare hostnames are OK to send to a hosted endpoint, but IPs and full
domains (FQDNs) are NOT — and secrets are stripped on every plane. This
scrubber runs ON TOP of the secret redactor for anything bound for the
knowledge plane.

The private plane (any OpenAI-compatible endpoint, typically local) uses
plain redact() — it does NOT strip identifiers.
"""
from nuncio.redactor import redact, scrub_for_knowledge_plane


def test_knowledge_plane_strips_ipv4():
    out, findings = scrub_for_knowledge_plane("service down on host at 10.0.0.2 port 5432")
    assert "10.0.0.2" not in out
    assert "«REDACTED:ip»" in out
    assert any(f["type"] == "ip" for f in findings)
    assert "port 5432" in out  # a port number is not an IP


def test_knowledge_plane_strips_fqdn_keeps_bare_hostname():
    out, findings = scrub_for_knowledge_plane("probe of host01.example.net failed; restart host01 now")
    assert "host01.example.net" not in out
    assert "«REDACTED:fqdn»" in out
    assert any(f["type"] == "fqdn" for f in findings)
    # bare hostname 'host01' (and the word 'restart') survive
    assert "restart host01 now" in out


def test_knowledge_plane_keeps_bare_container_names():
    text = "container sonarr crashed; check paperless-db and immich-server"
    out, findings = scrub_for_knowledge_plane(text)
    assert out == text  # no dots, no IPs, no secrets -> unchanged
    assert findings == []


def test_knowledge_plane_still_strips_secrets():
    secret = "sk-" "abcDEF1234567890abcDEF1234567890abcDEF12"
    out, findings = scrub_for_knowledge_plane(f"auth failed with {secret} on host01")
    assert secret not in out
    assert any(f["type"] == "api_key" for f in findings)
    assert "on host01" in out  # bare hostname kept


def test_knowledge_plane_realistic_alert_line():
    text = "PROBLEM host host01 service infisical-postgres at 10.0.0.2 via secrets.example.net CRIT"
    out, findings = scrub_for_knowledge_plane(text)
    assert "10.0.0.2" not in out
    assert "secrets.example.net" not in out
    assert "host host01 service infisical-postgres" in out  # bare names kept
    types = {f["type"] for f in findings}
    assert "ip" in types and "fqdn" in types


def test_private_plane_redact_does_NOT_strip_ip_or_hostname():
    # The private plane keeps identifiers; only secrets are removed.
    text = "host host01 at 10.0.0.2 on host01.example.net down"
    out, findings = redact(text)
    assert "10.0.0.2" in out
    assert "host01.example.net" in out
    assert findings == []
