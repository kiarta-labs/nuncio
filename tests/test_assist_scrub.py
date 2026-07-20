"""Assist-plane scrubber (nuncio.redactor.scrub_for_assist_plane) -- the
stricter, third scrubber used only for the optional out-of-band assist call.
Secrets first, then emails/IPs/FQDNs/usernames -> stable placeholders; bare
hostnames and container names survive untouched.
"""
import re

from nuncio.redactor import ScrubbedPayload, scrub_for_assist_plane


def test_secrets_are_redacted_first():
    secret = "sk-" + "abcDEF1234567890abcDEF1234567890abcDEF12"
    out = scrub_for_assist_plane(f"auth failed with {secret} on host01").text
    assert secret not in out
    assert "«REDACTED:api_key»" in out


def test_same_ip_gets_stable_placeholder_different_ip_gets_new_one():
    out = scrub_for_assist_plane("10.0.0.2 talked to 10.0.0.2 then to 10.0.0.3").text
    assert "10.0.0.2" not in out and "10.0.0.3" not in out
    assert out.count("<ip-1>") == 2
    assert "<ip-2>" in out


def test_fqdn_keeps_bare_first_label_strips_domain():
    payload = scrub_for_assist_plane("probe of svr01.lan failed")
    assert "svr01.lan" not in payload.text
    assert "svr01" in payload.text
    payload2 = scrub_for_assist_plane("connect to host01.example.net now")
    assert "host01.example.net" not in payload2.text
    assert "host01" in payload2.text


def test_email_becomes_placeholder_and_local_part_becomes_username_elsewhere():
    text = "notify kirit@example.com; user=kirit logged in"
    payload = scrub_for_assist_plane(text)
    assert "kirit@example.com" not in payload.text
    assert "<email-1>" in payload.text
    # the email's local part ("kirit") claims the first username slot
    assert "<user-1>" in payload.text
    assert "kirit" not in payload.text.replace("<user-1>", "")


def test_home_path_username_replaced():
    payload = scrub_for_assist_plane("check /home/kirit/logs for details")
    assert "/home/kirit/" not in payload.text
    assert "/home/<user-1>/" in payload.text


def test_user_kv_shape_replaced():
    payload = scrub_for_assist_plane("login attempt: user=bob failed")
    assert "user=bob" not in payload.text
    assert re.search(r"user=<user-\d+>", payload.text)


def test_email_then_user_kv_get_sequential_slots():
    text = "kirit@example.com opened a ticket for user=kirit; then user=bob logged in"
    payload = scrub_for_assist_plane(text)
    assert "user=<user-1>" in payload.text  # kirit (from the email) claims slot 1
    assert "user=<user-2>" in payload.text  # bob is new -> slot 2


def test_bare_hostnames_and_container_names_untouched():
    text = "container sonarr crashed; check paperless-db and immich-server"
    payload = scrub_for_assist_plane(text)
    assert payload.text == text
    assert payload.findings == ()


def test_findings_shape():
    payload = scrub_for_assist_plane("host at 10.0.0.2 and user=bob")
    assert isinstance(payload, ScrubbedPayload)
    types = {f["type"] for f in payload.findings}
    assert "ip" in types and "user" in types
    for f in payload.findings:
        assert set(f.keys()) == {"type", "count"}


# --- C-T1: composite hostile string -> nothing sensitive survives ----------

def test_composite_hostile_string_leaves_nothing_sensitive():
    secret = "sk-" + "abcDEF1234567890abcDEF1234567890abcDEF12"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    text = (
        f"secret={secret}\n"
        f"auth token: {jwt}\n"
        "hosts: 10.0.0.2, 10.0.0.3, 172.19.0.5\n"
        "domains: svr01.lan.example.net and host01.example.net\n"
        "contact kirit@example.com; check /home/kirit/logs\n"
        "«REDACTED:already» must survive untouched"
    )
    payload = scrub_for_assist_plane(text)
    out = payload.text
    assert secret not in out
    assert jwt not in out
    for ip in ("10.0.0.2", "10.0.0.3", "172.19.0.5"):
        assert ip not in out
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out)
    assert "svr01.lan.example.net" not in out
    assert "host01.example.net" not in out
    assert "kirit@example.com" not in out
    assert "«REDACTED:already»" in out  # guillemets from the secret pass survive intact


# --- FQDN pattern bounding (same RFC-1035 label/depth caps as the
# knowledge-plane rule, see test_knowledge_scrub.py) -----------------------

import time  # noqa: E402


def test_assist_scrub_is_fast_on_dotted_flood():
    text = "a." * 8000  # 16,000 chars of dotted labels
    start = time.monotonic()
    scrub_for_assist_plane(text)
    assert time.monotonic() - start < 2.0


def test_assist_fqdn_bare_label_survives_after_bounding():
    # (kept under 20 chars so the entropy backstop -- a separate, pre-existing
    # heuristic in redact(), stage 1 of this scrubber -- doesn't fire first
    # and consume the whole token before the FQDN stage ever sees it)
    payload = scrub_for_assist_plane("probe of svr01.example.net failed")
    assert "svr01.example.net" not in payload.text
    assert "svr01" in payload.text
    assert any(f["type"] == "fqdn" for f in payload.findings)
