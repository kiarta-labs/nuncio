"""Correlation scoring: the ratified causal-entity-gate model (2026-07-20).
A row enters the CAUSAL tier only via fingerprint recurrence, unit/service
equality, or a declared dependency edge -- host co-location is a weak
GROUPING label only ("also active on <host>"), never a cause. Rank-only
signals (tokens/category/paths/host-grouping) order rows that already
passed the gate; they never admit a row on their own. See
nuncio.correlate's module docstring for the full model."""
from nuncio.correlate import rank_correlated


ALERT = {"host": "host01", "service": "infisical-postgres",
         "output": "FATAL: all AuxiliaryProcs are in use"}
TOKENS = ["FATAL", "AuxiliaryProcs"]


def rows(*payloads, base=1000.0):
    # oldest-first, 30s apart, like store.recent()
    return [(f"k{i}", p, base - 30.0 * (len(payloads) - i)) for i, p in enumerate(payloads)]


def rows9(*items, base=1000.0):
    """items: (payload, source, category, severity, fingerprint, host, service)
    tuples -- the current store.recent() 9-tuple shape."""
    n = len(items)
    out = []
    for i, (payload, source, category, severity, fp, host, service) in enumerate(items):
        out.append((f"k{i}", payload, base - 30.0 * (n - i), source, category, severity,
                     fp, host, service))
    return out


def test_same_host_alone_is_grouping_not_causal():
    # host co-location with no shared service/unit/fingerprint/dep is a
    # LABEL ("also active on <host>"), never promoted to a causal reason;
    # a row with no host/service/unit overlap at all is excluded entirely.
    r = rows(
        "[PROBLEM] workstation01 CPU load high",
        "[PROBLEM] host01 GPF escalation on host",
    )
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert len(ranked) == 1  # workstation01 row: no host/service/unit overlap -- excluded
    assert "host01 GPF" in ranked[0]
    assert "also active on host01" in ranked[0]
    assert "same host" not in ranked[0]  # the retired reason string


def test_token_overlap_alone_never_admits_a_row():
    # Rank-only signals (error-token similarity here) can never admit a row
    # on their own -- the row has no gate hit AND no host match.
    r = rows("[PROBLEM] gitea-db FATAL wedge detected")
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert ranked == []


def test_token_overlap_annotates_an_already_gated_row():
    # Combined with a real gate hit (same service here), token similarity
    # still shows up as an additional reason, ranking the row within tier 0.
    r = rows("[PROBLEM] infisical-postgres FATAL wedge detected")
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert len(ranked) == 1
    assert "same service" in ranked[0]
    assert "similar error" in ranked[0].lower()
    assert "fatal" in ranked[0].lower()


def test_same_service_annotated():
    r = rows("[RECOVERY] infisical-postgres back up")
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    assert "same service" in ranked[0]


def test_unrelated_alert_is_excluded_not_just_ranked_last():
    r = rows(
        "[PROBLEM] wifi-ap3 radio DFS event",     # no host/service/unit overlap -- excluded
        "[PROBLEM] host01 FATAL postgres wedge",  # host-grouped only (no service/unit match)
    )
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert len(ranked) == 1
    assert "host01 FATAL" in ranked[0]
    assert "also active on host01" in ranked[0]


def test_caps_to_top_n_across_tiers():
    # 30 rows all sharing the alert's service -- all gate (tier 0), capped
    # to top_n same as before the model change.
    r = rows(*[f"[PROBLEM] infisical-postgres noise event {i}" for i in range(30)])
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0, top_n=5)
    assert len(ranked) == 5


def test_recency_breaks_ties():
    r = rows(
        "[PROBLEM] host01 older event",
        "[PROBLEM] host01 newer event",
    )
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    assert "newer" in ranked[0]


def test_host_match_is_word_bounded():
    # alert host 'ap' must not match inside 'apprise' -- and with no other
    # gate signal, the row is excluded entirely (not merely unlabeled).
    ranked = rank_correlated(
        rows("[PROBLEM] apprise container restarting"),
        {"host": "ap", "service": None, "output": ""}, tokens=[], now=1000.0)
    assert ranked == []


def test_deterministic():
    r = rows("[PROBLEM] host01 a", "[PROBLEM] host01 b")
    a = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    b = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert a == b


def test_never_raises_on_garbage_rows():
    ranked = rank_correlated([("k", None, None), ("k2", 42, "x")],
                             ALERT, tokens=TOKENS, now=1000.0)
    assert isinstance(ranked, list)  # degrade, never raise


def test_empty_rows():
    assert rank_correlated([], ALERT, tokens=TOKENS, now=1000.0) == []


# --- B2: structured 7-tuple rows + new signals ---

def rows7(*items, base=1000.0):
    """items: (payload, source, category, severity, fingerprint) tuples."""
    n = len(items)
    out = []
    for i, (payload, source, category, severity, fp) in enumerate(items):
        out.append((f"k{i}", payload, base - 30.0 * (n - i), source, category, severity, fp))
    return out


def test_3tuple_back_compat_host_only_is_grouping_not_gate():
    # A legacy 3-tuple row (no host/service columns) with only a host-text
    # match in the summary is grouping ONLY -- the legacy regex fallback can
    # never gate via host, matching the column-based path's posture.
    r = rows("[PROBLEM] host01 GPF escalation")
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert "also active on host01" in ranked[0]
    assert "same host" not in ranked[0]


def test_3tuple_back_compat_service_text_still_gates():
    # The legacy regex fallback CAN gate via service/unit/dependency text --
    # only host is demoted.
    r = rows("[PROBLEM] infisical-postgres FATAL wedge")
    ranked = rank_correlated(r, ALERT, tokens=TOKENS, now=1000.0)
    assert "same service" in ranked[0]


def test_same_fingerprint_signal():
    alert_fp = "abc1234567890def"
    r = rows7(
        ("[PROBLEM] unrelated event", None, None, None, "zzz"),
        ("[PROBLEM] recurring wedge again", None, None, None, alert_fp),
    )
    alert = dict(ALERT, output="FATAL: all AuxiliaryProcs are in use")
    # patch: force the alert's own computed fingerprint to match row 2's fp
    import nuncio.correlate as corr_mod
    orig = corr_mod._compute_fingerprint
    corr_mod._compute_fingerprint = lambda a: alert_fp
    try:
        ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    finally:
        corr_mod._compute_fingerprint = orig
    assert "same recurring signature" in ranked[0]
    assert "recurring wedge" in ranked[0]


def test_same_category_alone_never_admits_a_row():
    # category is rank-only -- with no gate hit and no host match, the row
    # is excluded outright, never merely unlabeled.
    r = rows7(("[PROBLEM] gitea-db trouble", None, "container", None, None))
    alert = dict(ALERT, category="container", output="")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []


def test_same_category_annotates_an_already_gated_row():
    r = rows7(("[PROBLEM] infisical-postgres gitea-db trouble", None, "container", None, None))
    alert = dict(ALERT, category="container", output="")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert "same service" in ranked[0]
    assert "same category (container)" in ranked[0]


# --- regression: production bug #2 survived on the service regex-fallback
# path -- a host-level alert's service="-" placeholder built a bare `\b-\b`
# regex via _word_re(service), which matches the literal hyphen in unrelated
# hostnames/summaries ("db-primary", "TEST-NUNCIO", ...) whenever the store
# row has no `service` column (NULL -- legacy 3-tuple rows, or a 9-tuple row
# from a source that never populated it, e.g. Grafana with no alertname or
# /ingest/generic). host_re and unit_re were already guarded against this
# (real_host()/resolve_unit_strict() reject "-"); only service_re used the
# raw, unguarded `service` value. See nuncio.correlate's module docstring.

def test_placeholder_service_never_gates_9tuple_null_service_row():
    alert = dict(ALERT, host="-", service="-")
    r = rows9(("[PROBLEM] db-primary replication lag", None, None, None, None, None, None))
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []
    assert not any("same service" in line for line in ranked)


def test_placeholder_service_never_gates_3tuple_legacy_row():
    alert = dict(ALERT, host="-", service="-")
    r = rows("[PROBLEM] TEST-NUNCIO synthetic canary fired")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []
    assert not any("same service" in line for line in ranked)


def test_placeholder_host_and_service_yield_zero_causal_chains():
    # End-to-end shape from the review: a CheckMK HOST-level alert (both
    # host and service are the "-" placeholder) against two unrelated,
    # NULL-service store rows must produce zero causal (or grouping) hits --
    # not a fabricated root/symptom chain.
    alert = dict(ALERT, host="-", service="-")
    r = rows9(
        ("[PROBLEM] db-primary replication lag", None, None, None, None, None, None),
        ("[PROBLEM] TEST-NUNCIO synthetic canary fired", None, None, None, None, None, None),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []


def test_same_unit_signal():
    r = rows7(("[PROBLEM] infisical-postgres unit trouble", None, None, None, None))
    alert = {"host": "", "service": "Docker container infisical-postgres", "output": ""}
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert "same unit" in ranked[0]


def test_shared_path_alone_never_admits_a_row():
    r = rows7(("[PROBLEM] mount /mnt/photon/appdata lost", None, None, None, None))
    alert = dict(ALERT, output="CIFS mount /mnt/photon/appdata not present")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []


def test_shared_path_annotates_an_already_gated_row():
    r = rows7(("[PROBLEM] infisical-postgres mount /mnt/photon/appdata lost", None, None, None, None))
    alert = dict(ALERT, output="CIFS mount /mnt/photon/appdata not present")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert "same service" in ranked[0]
    assert "shared path: /mnt/photon/appdata" in ranked[0]


def test_dependency_hint_signal():
    r = rows7(("[PROBLEM] infisical-postgres FATAL wedge", None, None, None, None))
    alert = dict(ALERT, service="infisical", output="cannot connect to db")
    deps = {"infisical": ["infisical-postgres"]}
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert "upstream dependency of infisical" in ranked[0]


def test_no_dependency_hint_when_deps_absent():
    r = rows7(("[PROBLEM] infisical-postgres FATAL wedge", None, None, None, None))
    alert = dict(ALERT, service="infisical", output="cannot connect to db")
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=None)
    assert "upstream dependency" not in ranked[0]


def test_causal_hint_earliest_root_later_symptom():
    # Both rows gate via same-service text (legacy 7-tuple fallback) --
    # the causal hint is temporal among the GATED rows.
    r = rows7(
        ("[PROBLEM] infisical-postgres disk pressure rising", None, None, None, None),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None),
    )
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    joined = " ".join(ranked)
    assert "possible root (earliest)" in joined
    assert "possible symptom (later)" in joined
    assert "on host" not in joined  # the retired "(earliest on host)" wording


def test_causal_hint_never_applies_to_host_grouped_only_rows():
    # Two host-grouped-only rows (no service/unit match) plus a single
    # gated row -- the hint requires >=2 GATED rows, so no hint fires at
    # all here, and even if it did, tier-1 grouping rows are structurally
    # unreachable by it.
    r = rows7(
        ("[PROBLEM] host01 disk pressure rising", None, None, None, None),
        ("[PROBLEM] host01 unrelated wobble", None, None, None, None),
    )
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    joined = " ".join(ranked)
    assert "also active on host01" in joined
    assert "possible root" not in joined
    assert "possible symptom" not in joined


def test_causal_hint_only_among_gated_rows_not_grouped_ones():
    # 2 gated (same-service) rows + 2 host-grouped-only rows: the hint must
    # land on the gated pair only, never on the grouping-only lines.
    r = rows7(
        ("[PROBLEM] host01 unrelated wobble one", None, None, None, None),
        ("[PROBLEM] infisical-postgres disk pressure rising", None, None, None, None),
        ("[PROBLEM] host01 unrelated wobble two", None, None, None, None),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None),
    )
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    gated_lines = [ln for ln in ranked if "same service" in ln]
    grouped_lines = [ln for ln in ranked if "also active on host01" in ln]
    assert len(gated_lines) == 2
    assert any("possible root (earliest)" in ln for ln in gated_lines)
    assert any("possible symptom (later)" in ln for ln in gated_lines)
    assert not any("possible root" in ln or "possible symptom" in ln for ln in grouped_lines)


def test_garbage_7tuple_rows_never_poison():
    ranked = rank_correlated(
        [("k", None, None, None, None, None, None), ("k2", 42, "x", 1, 2, 3, 4)],
        ALERT, tokens=TOKENS, now=1000.0)
    assert isinstance(ranked, list)


def test_weight_ordering_fingerprint_gates_unrelated_row_is_excluded():
    # A fingerprint match gates (tier 0); a row with no gate hit and no host
    # match is excluded outright, so it can never outrank -- or even
    # appear alongside -- the gated row.
    import nuncio.correlate as corr_mod
    alert_fp = "deadbeefcafefeed"
    r = rows7(
        ("[PROBLEM] unrelated no-signal row", None, None, None, None),
        ("[PROBLEM] host01 recurring issue", None, None, None, alert_fp),
    )
    orig = corr_mod._compute_fingerprint
    corr_mod._compute_fingerprint = lambda a: alert_fp
    try:
        ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    finally:
        corr_mod._compute_fingerprint = orig
    assert len(ranked) == 1
    assert "recurring issue" in ranked[0]


# --- Phase B: age suffix on every rendered line ---

def test_age_suffix_minutes_under_90():
    r = rows("[PROBLEM] host01 GPF escalation")  # 30s before now=1000.0
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    assert "; 0m ago" in ranked[0]


def test_age_suffix_hours_at_90_minutes_or_more():
    r = [("k0", "[PROBLEM] host01 GPF escalation", 1000.0 - 7200.0)]  # 2h old
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    assert "; 2.0h ago" in ranked[0]


def test_age_suffix_precedes_causal_hint():
    r = rows7(
        ("[PROBLEM] infisical-postgres disk pressure rising", None, None, None, None),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None),
    )
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    joined = " ".join(ranked)
    assert "ago; possible root (earliest)" in joined
    assert "ago; possible symptom (later)" in joined


def test_age_suffix_omitted_on_garbage_created_at():
    r = [("k0", "[PROBLEM] host01 GPF escalation", "not-a-timestamp")]
    ranked = rank_correlated(r, ALERT, tokens=[], now=1000.0)
    assert " ago" not in ranked[0]


# --- Phase 3.7: the full ratified-model test matrix (9-tuple / column-based) ---

def test_single_host_bleed_regression_zero_causal_hints():
    # The #2 production bug, one level up: many unrelated alerts on the
    # SAME host (a near-universal condition on a single-host fleet) must
    # NEVER fabricate a causal chain. Every surfaced row is grouping-only.
    alert = {"host": "svr", "service": "nuncio", "output": ""}
    r = rows9(*[
        (f"[PROBLEM] unrelated-check-{i} trouble", None, None, None, None, "svr", f"unrelated-check-{i}")
        for i in range(10)
    ])
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, top_n=20)
    assert len(ranked) == 10
    for line in ranked:
        assert "also active on svr" in line
        assert "possible root" not in line
        assert "possible symptom" not in line
        assert "same service" not in line
        assert "same unit" not in line
        assert "same recurring signature" not in line
        assert "upstream dependency" not in line


def test_placeholder_host_regression_no_matching_of_any_kind():
    # Live bug #2: an instance-less alert (host="-") must never match ANY
    # row's host, even one whose SERVICE literally contains a hyphenated
    # name like the ones that used to false-positive on the old `\b-\b`
    # regex ("TEST-NUNCIO", "canary-drill", dotted IPs).
    alert = {"host": "-", "service": "-", "output": ""}
    r = rows9(
        ("[PROBLEM] TEST-NUNCIO synthetic probe", None, None, None, None, "-", "TEST-NUNCIO"),
        ("[PROBLEM] canary-drill fired", None, None, None, None, "-", "canary-drill"),
        ("[PROBLEM] 10.13.37.2 unreachable", None, None, None, None, "-", "10.13.37.2"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert ranked == []


def test_same_unit_via_columns_is_causal():
    alert = {"host": "svr", "service": "Docker container grafana", "output": ""}
    r = rows9(
        ("[PROBLEM] grafana unhealthy", None, None, None, None, "svr", "grafana"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    assert len(ranked) == 1
    assert "same unit" in ranked[0]


def test_dependency_edge_gates_causally_across_hosts():
    # The sanctioned cross-host causal path: a declared dependency_hints
    # edge gates even when the upstream row is on a DIFFERENT host.
    alert = {"host": "svr", "service": "infisical", "output": "cannot connect to db"}
    r = rows9(
        ("[PROBLEM] infisical-postgres FATAL wedge", None, None, None, None,
         "kprintr", "infisical-postgres"),
    )
    deps = {"infisical": ["infisical-postgres"]}
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "upstream dependency of infisical" in ranked[0]
    assert "also active on" not in ranked[0]  # different host -- no grouping label either


def test_dependency_edge_eligible_for_root_symptom_hint():
    alert = {"host": "svr", "service": "infisical", "output": "cannot connect to db"}
    deps = {"infisical": ["infisical-postgres"]}
    r = rows9(
        ("[PROBLEM] infisical-postgres pressure rising", None, None, None, None,
         "kprintr", "infisical-postgres"),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None,
         "kprintr", "infisical-postgres"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    joined = " ".join(ranked)
    assert "possible root (earliest)" in joined
    assert "possible symptom (later)" in joined


# --- bidirectional dependency correlation (2026-07-20 ratified extension):
# a declared dependency_hints edge gates in BOTH directions -- an alert on
# the upstream service must also causally link its declared dependents. ---

def test_downstream_dependency_gates_causally_via_columns():
    # Alert fires on the UPSTREAM service (infisical-postgres); the candidate
    # row is a declared DEPENDENT (infisical depends on infisical-postgres) --
    # this direction previously never gated at all.
    alert = {"host": "svr", "service": "infisical-postgres", "output": "wedge"}
    deps = {"infisical": ["infisical-postgres"]}
    r = rows9(
        ("[PROBLEM] infisical unreachable", None, None, None, None, "svr", "infisical"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "declared dependent of infisical-postgres" in ranked[0]


def test_downstream_dependency_gates_causally_across_hosts():
    alert = {"host": "svr", "service": "infisical-postgres", "output": "wedge"}
    deps = {"infisical": ["infisical-postgres"]}
    r = rows9(
        ("[PROBLEM] infisical unreachable", None, None, None, None, "kprintr", "infisical"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "declared dependent of infisical-postgres" in ranked[0]
    assert "also active on" not in ranked[0]  # different host -- no grouping label either


def test_downstream_dependency_legacy_fallback_via_summary_regex():
    # Legacy 7-tuple row (no host/service columns): the downstream direction
    # must still gate via a summary-text match on the DEPENDENT service name
    # -- never via a host match (7-tuple rows carry no host column at all).
    r = rows7(("[PROBLEM] infisical unreachable", None, None, None, None))
    alert = dict(ALERT, service="infisical-postgres", output="disk pressure")
    deps = {"infisical": ["infisical-postgres"]}
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert "declared dependent of infisical-postgres" in ranked[0]


def test_existing_upstream_direction_still_gates_unchanged():
    # Regression: the pre-existing upstream direction (alert on the
    # DOWNSTREAM service, candidate row is the declared upstream) must keep
    # working exactly as before this change.
    alert = {"host": "svr", "service": "infisical", "output": "cannot connect to db"}
    deps = {"infisical": ["infisical-postgres"]}
    r = rows9(
        ("[PROBLEM] infisical-postgres FATAL wedge", None, None, None, None, "svr", "infisical-postgres"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "upstream dependency of infisical" in ranked[0]


def test_bidirectional_deps_present_but_row_has_no_declared_edge_stays_grouping_only():
    # Anti-fanout regression, one level up: a `deps` map is now present (so
    # both directions are computed), but the candidate row on the SAME host
    # has no declared edge in EITHER direction with the alert's service --
    # it must still land tier-1 (grouping-only), never tier-0 causal.
    alert = {"host": "svr", "service": "infisical", "output": ""}
    deps = {"infisical": ["infisical-postgres"]}  # unrelated to the row below
    r = rows9(
        ("[PROBLEM] unrelated-check trouble", None, None, None, None, "svr", "unrelated-check"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "also active on svr" in ranked[0]
    assert "dependent" not in ranked[0]
    assert "upstream dependency" not in ranked[0]
    assert "possible root" not in ranked[0]
    assert "possible symptom" not in ranked[0]


def test_bidirectional_dependency_root_symptom_hint_across_both_ends():
    # One row gated via the upstream direction, another via the new
    # downstream direction -- the temporal root/symptom hint must still
    # apply across both, landing on the earliest GATED row regardless of
    # which direction gated it.
    alert = {"host": "svr", "service": "infisical", "output": "cannot connect to db"}
    deps = {
        "infisical": ["infisical-postgres"],       # infisical depends on postgres (upstream)
        "infisical-frontend": ["infisical"],        # frontend depends on infisical (downstream of alert)
    }
    r = rows9(
        ("[PROBLEM] infisical-postgres pressure rising", None, None, None, None,
         "svr", "infisical-postgres"),
        ("[PROBLEM] infisical-frontend errors follow", None, None, None, None,
         "svr", "infisical-frontend"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    joined = " ".join(ranked)
    assert "upstream dependency of infisical" in joined
    assert "declared dependent of infisical" in joined
    assert "possible root (earliest)" in joined
    assert "possible symptom (later)" in joined


def test_dependency_hit_in_both_directions_prefers_upstream_wording_and_single_weight():
    # A (contrived) two-way declared edge: the candidate row is BOTH an
    # upstream of the alert's service AND a declared dependent of it. The
    # weight must be added exactly once (not double-counted), and the
    # rendered reason must prefer the upstream wording.
    alert = {"host": "svr", "service": "a", "output": ""}
    deps = {"a": ["b"], "b": ["a"]}
    r = rows9(
        ("[PROBLEM] b trouble", None, None, None, None, "svr", "b"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0, deps=deps)
    assert len(ranked) == 1
    assert "upstream dependency of a" in ranked[0]
    assert "declared dependent of a" not in ranked[0]
    assert ranked[0].count("dependency of a") + ranked[0].count("dependent of a") == 1


def test_host_only_colocation_never_roots_even_when_earliest():
    # A host-grouped-only row that is the temporally EARLIEST row in the
    # whole window must still never get a causal annotation -- it's ranked
    # below every tier-0 row and structurally excluded from the hint.
    alert = {"host": "svr", "service": "infisical-postgres", "output": ""}
    r = rows9(
        ("[PROBLEM] svr unrelated wobble (earliest)", None, None, None, None, "svr", "wobble-check"),
        ("[PROBLEM] infisical-postgres pressure rising", None, None, None, None, "svr", "infisical-postgres"),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None, "svr", "infisical-postgres"),
    )
    ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    tier0 = [ln for ln in ranked if "same service" in ln]
    tier1 = [ln for ln in ranked if "also active on svr" in ln and "same service" not in ln]
    assert len(tier0) == 2 and len(tier1) == 1
    assert ranked.index(tier0[0]) < ranked.index(tier1[0])  # tier 0 always precedes tier 1
    assert "possible root" not in tier1[0] and "possible symptom" not in tier1[0]
    assert any("possible root (earliest)" in ln for ln in tier0)


def test_rank_only_signals_never_admit_a_row_columns():
    # Token/category/path overlap with a DIFFERENT host and no gate key:
    # excluded entirely, never merely deprioritized.
    alert = {"host": "svr", "service": "infisical-postgres", "category": "container",
             "output": "FATAL /mnt/photon/appdata error"}
    r = rows9(
        ("[PROBLEM] FATAL /mnt/photon/appdata trouble", None, "container", None, None,
         "kprintr", "unrelated-thing"),
    )
    ranked = rank_correlated(r, alert, tokens=["FATAL"], now=1000.0)
    assert ranked == []


def test_fingerprint_gates_via_columns():
    import nuncio.correlate as corr_mod
    alert = {"host": "svr", "service": "infisical-postgres", "output": "wedge"}
    fp = "cafebabe12345678"
    r = rows9(
        ("[PROBLEM] recurring wedge again", None, None, None, fp, "kprintr", "unrelated"),
    )
    orig = corr_mod._compute_fingerprint
    corr_mod._compute_fingerprint = lambda a: fp
    try:
        ranked = rank_correlated(r, alert, tokens=[], now=1000.0)
    finally:
        corr_mod._compute_fingerprint = orig
    assert len(ranked) == 1
    assert "same recurring signature" in ranked[0]


def test_determinism_pin_mixed_tiers_byte_identical_across_runs():
    alert = {"host": "svr", "service": "infisical-postgres", "output": "FATAL wedge"}
    r = rows9(
        ("[PROBLEM] svr unrelated wobble one", None, None, None, None, "svr", "wobble-1"),
        ("[PROBLEM] infisical-postgres pressure rising", None, None, None, None, "svr", "infisical-postgres"),
        ("[PROBLEM] svr unrelated wobble two", None, None, None, None, "svr", "wobble-2"),
        ("[PROBLEM] infisical-postgres wedge follows", None, None, None, None, "svr", "infisical-postgres"),
        ("[PROBLEM] excluded-elsewhere trouble", None, None, None, None, "kprintr", "elsewhere"),
    )
    a = rank_correlated(r, alert, tokens=["FATAL"], now=1000.0, top_n=8)
    b = rank_correlated(r, alert, tokens=["FATAL"], now=1000.0, top_n=8)
    assert a == b
    assert len(a) == 4  # the different-host, no-overlap row is excluded
