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


# --- FQDN pattern bounding (RFC-1035 label + depth caps kill the outer-star
# backtracking that made the old unbounded fqdn regex O(n^2)) --------------

import time  # noqa: E402


def test_knowledge_scrub_is_fast_on_dotted_flood():
    text = "a." * 8000  # 16,000 chars of dotted labels, no closing known TLD
    start = time.monotonic()
    scrub_for_knowledge_plane(text)
    assert time.monotonic() - start < 2.0


def test_knowledge_scrub_fqdn_parity_after_bounding():
    cases = [
        ("host.example.net", True),                                    # stripped
        ("svr01.lan.example.net", True),                                # stripped
        ("a." * 15 + "example.net", True),                              # deep, <=16 labels, stripped
        ("multi-hyphen-name.example.net", True),                        # hyphens mid-label, stripped
        ("x" * 63 + ".example.net", True),                              # 63-char label, still matches
        ("host01", False),                                              # bare host, kept
        ("example.net", True),                                          # two-label domain, stripped
        ("not-a-domain-at-all", False),                                 # hyphens ok, no known TLD, kept
        ("10.0.0.2", False),                                            # IP handled by the ip rule, not fqdn
    ]
    for host, should_strip in cases:
        out, _ = scrub_for_knowledge_plane(f"probe of {host} failed")
        if should_strip:
            assert host not in out, f"expected {host!r} to be stripped"
        else:
            assert host in out or "«REDACTED:ip»" in out, f"expected {host!r} to survive (or be IP-redacted)"

    # A 64-char label is one char over the RFC-1035 cap: the label itself
    # never matches as part of an fqdn, but a valid domain suffix following
    # it (".example.net") is still its own independent match and gets
    # stripped -- the long label is not "protected" by being attached to it.
    long_label = "x" * 64
    out, _ = scrub_for_knowledge_plane(f"probe of {long_label}.example.net failed")
    assert long_label in out           # the oversized label itself survives
    assert "example.net" not in out    # but the domain suffix after it is stripped
