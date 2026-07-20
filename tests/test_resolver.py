"""Entity resolution (deterministic, pure): normalize an alert's service name to
a likely container/log-stream name, and extract salient error tokens from the
alert output for use as extra log-search / correlation terms."""
from nuncio.resolver import resolve_unit, resolve_unit_strict, extract_error_tokens


# --- resolve_unit ---

def test_plain_container_service_passes_through():
    assert resolve_unit({"service": "infisical-postgres"}) == "infisical-postgres"


def test_checkmk_docker_container_prefix_stripped():
    assert resolve_unit({"service": "Docker container infisical-postgres"}) == "infisical-postgres"


def test_host_slash_service_takes_service_part():
    assert resolve_unit({"service": "host01/sonarr"}) == "sonarr"


def test_systemd_suffix_stripped():
    assert resolve_unit({"service": "gitea.service"}) == "gitea"


def test_status_suffix_and_service_prefix_stripped():
    assert resolve_unit({"service": "Systemd Service nginx status"}) == "nginx"


def test_compose_scale_suffix_stripped():
    assert resolve_unit({"service": "paperless-webserver_1"}) == "paperless-webserver"


def test_falls_back_to_host_when_no_service():
    assert resolve_unit({"host": "host01"}) == "host01"


def test_none_when_nothing_usable():
    assert resolve_unit({}) is None
    assert resolve_unit({"service": "", "host": ""}) is None


def test_result_is_lowercased():
    assert resolve_unit({"service": "Container Vector"}) == "vector"


def test_deterministic_same_input_same_output():
    a = {"service": "Docker container grafana"}
    assert resolve_unit(a) == resolve_unit(a) == "grafana"


# --- Phase 4.1: resolve_unit now prefers alert["unit"] (cleaned/lowercased)
# before service/host -- an adapter/operator can name the real log unit so
# the alert name stops masquerading as one (openobserve.py's new `unit`
# template field feeds this). Order: unit > service > host, same
# prefix/suffix normalization + lowercasing as every other source. ---

def test_resolve_unit_prefers_unit_field_over_service():
    assert resolve_unit({"unit": "grafana", "service": "syslog-flood"}) == "grafana"


def test_resolve_unit_prefers_unit_field_over_host():
    assert resolve_unit({"unit": "grafana", "host": "svr"}) == "grafana"


def test_resolve_unit_unit_field_is_cleaned_and_lowercased():
    assert resolve_unit({"unit": "Docker container Vector"}) == "vector"
    assert resolve_unit({"unit": "gitea.service"}) == "gitea"


def test_resolve_unit_falls_back_to_service_when_no_unit():
    assert resolve_unit({"service": "sonarr"}) == "sonarr"


def test_resolve_unit_falls_back_to_host_when_no_unit_or_service():
    assert resolve_unit({"host": "host01"}) == "host01"


def test_resolve_unit_empty_unit_falls_through_to_service():
    assert resolve_unit({"unit": "", "service": "sonarr"}) == "sonarr"


# --- resolve_unit_strict: the Phase 3 gate identity -- unit/service only,
# NEVER the host fallback (guards against smuggling host back into the
# causal-entity gate as a fake "unit") ---

def test_resolve_unit_strict_plain_service():
    assert resolve_unit_strict({"service": "infisical-postgres"}) == "infisical-postgres"


def test_resolve_unit_strict_prefers_unit_field():
    assert resolve_unit_strict({"unit": "grafana", "service": "Docker container vector"}) == "grafana"


def test_resolve_unit_strict_normalizes_like_resolve_unit():
    assert resolve_unit_strict({"service": "Docker container infisical-postgres"}) == "infisical-postgres"
    assert resolve_unit_strict({"unit": "gitea.service"}) == "gitea"


def test_resolve_unit_strict_none_when_only_host_present():
    # the whole point: a host-only alert must NOT resolve a fake unit from
    # the host field -- resolve_unit (non-strict) WOULD return "host01" here.
    assert resolve_unit_strict({"host": "host01"}) is None
    assert resolve_unit({"host": "host01"}) == "host01"  # contrast with the non-strict sibling


def test_resolve_unit_strict_none_for_placeholder_service():
    assert resolve_unit_strict({"service": "-"}) is None
    assert resolve_unit_strict({"service": "---"}) is None


def test_resolve_unit_strict_none_when_nothing_usable():
    assert resolve_unit_strict({}) is None
    assert resolve_unit_strict({"service": "", "host": "host01"}) is None


def test_resolve_unit_strict_deterministic():
    a = {"unit": "Docker container grafana"}
    assert resolve_unit_strict(a) == resolve_unit_strict(a) == "grafana"


def test_resolve_unit_strict_never_raises_on_garbage():
    assert resolve_unit_strict(None) is None
    assert resolve_unit_strict({"unit": None, "service": None}) is None


# --- extract_error_tokens ---

def test_extracts_error_keywords_and_identifiers():
    toks = extract_error_tokens(
        {"output": "FATAL: all AuxiliaryProcs are in use"})
    lowered = [t.lower() for t in toks]
    assert "fatal" in lowered
    assert "AuxiliaryProcs" in toks  # CamelCase identifier kept verbatim


def test_extracts_network_error_words_and_http_codes():
    toks = extract_error_tokens(
        {"output": "connection refused; upstream timeout; HTTP 502"})
    lowered = [t.lower() for t in toks]
    assert "refused" in lowered and "timeout" in lowered and "502" in lowered


def test_mount_and_oom_tokens():
    toks = [t.lower() for t in extract_error_tokens(
        {"output": "CIFS mount lost; process OOM-killed"})]
    assert "mount" in toks and "oom" in toks


def test_dedup_and_first_seen_order():
    toks = extract_error_tokens({"output": "error error TIMEOUT error Timeout"})
    lowered = [t.lower() for t in toks]
    assert lowered.count("error") == 1 and lowered.count("timeout") == 1
    assert lowered.index("error") < lowered.index("timeout")  # first-seen order


def test_capped_token_count():
    blob = " ".join(f"WeirdIdentifier{i}Thing" for i in range(50))
    assert len(extract_error_tokens({"output": blob}, max_tokens=8)) <= 8


def test_no_tokens_on_benign_output():
    assert extract_error_tokens({"output": "all is well"}) == []


def test_never_raises_on_garbage():
    assert extract_error_tokens({"output": None}) == []
    assert extract_error_tokens({}) == []
