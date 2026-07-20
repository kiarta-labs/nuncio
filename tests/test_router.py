"""Provider-agnostic plane router — where the privacy invariant lives in code.

Invariant: real alert content ALWAYS routes to the private plane (any
OpenAI-compatible endpoint the operator configures, typically local); a
second, typically-hosted knowledge-plane endpoint is reachable ONLY via the
fixed classification table (allowlist by construction) and ONLY when the
knowledge plane is explicitly enabled. There is no code path where
identifier-bearing content can select a knowledge-plane alias.
"""
import pytest
from nuncio.router import DEFAULT_CLASSIFICATION_TABLE, Router

TABLE = {
    "cifs_mount_race": "common causes and standard fixes for a SMB/CIFS mount race at boot on Linux",
    "postgres_wedge": "common causes of PostgreSQL failing to start with auxiliary process exhaustion",
}


def make_router(knowledge_enabled=False):
    return Router(private_alias="local-model",
                  knowledge_alias="knowledge-model",
                  classification_table=TABLE,
                  knowledge_enabled=knowledge_enabled)


def test_alert_enrichment_always_routes_private():
    r = make_router(knowledge_enabled=True)  # even with knowledge enabled...
    assert r.route_alert() == "local-model"  # ...alert content is ALWAYS private


def test_route_alert_never_returns_knowledge_alias():
    r = make_router(knowledge_enabled=True)
    assert r.route_alert() != r.knowledge_alias


def test_knowledge_plane_disabled_by_default_returns_none():
    r = make_router()  # default disabled
    assert r.route_knowledge("cifs_mount_race") is None


def test_knowledge_plane_enabled_valid_class_returns_alias_and_generic_string():
    r = make_router(knowledge_enabled=True)
    result = r.route_knowledge("cifs_mount_race")
    assert result is not None
    alias, prompt = result
    assert alias == "knowledge-model"
    assert prompt == TABLE["cifs_mount_race"]  # the TABLE's generic string, nothing else


def test_knowledge_plane_unknown_class_returns_none_even_if_enabled():
    # allowlist-by-construction: an unknown key (e.g. raw alert text) can't reach the knowledge plane
    r = make_router(knowledge_enabled=True)
    assert r.route_knowledge("host host01 10.0.0.2 down") is None


def test_knowledge_plane_never_echoes_caller_text():
    # Passing something that isn't a table KEY must never produce a knowledge-plane
    # prompt built from that text — the only knowledge-plane-bound text is a TABLE VALUE.
    r = make_router(knowledge_enabled=True)
    for probe in ("host01.example.net", "sk-secret", "", None):
        assert r.route_knowledge(probe) is None


# --- Phase C: DEFAULT_CLASSIFICATION_TABLE -- closes the silent-no-op gap
# (a fresh install's operator table used to default to {}, so enabling the
# knowledge plane did NOTHING; nuncio.config.build_router merges the built-in
# default UNDER any operator table). ---

def test_default_classification_table_has_one_entry_per_builtin_category():
    # nuncio.model.categorize's builtin categories: hardware/storage/network/
    # container/generic -- the knowledge plane must route ALL of them out of
    # the box, not just the ones an operator happened to author.
    assert set(DEFAULT_CLASSIFICATION_TABLE) == {"hardware", "storage", "network", "container", "generic"}


def test_default_classification_table_entries_are_generic_identifier_free():
    # Anonymisation guarantee applies to the built-in table too: running each
    # entry through the SAME scrubber the knowledge plane applies to every
    # outbound call must be a no-op -- if it changed anything, the entry
    # itself contained an IP/FQDN, i.e. was not actually identifier-free.
    from nuncio.redactor import scrub_for_knowledge_plane
    for category, prompt in DEFAULT_CLASSIFICATION_TABLE.items():
        assert isinstance(prompt, str) and prompt
        scrubbed, findings = scrub_for_knowledge_plane(prompt)
        assert scrubbed == prompt
        assert findings == []


def test_a_category_with_no_operator_entry_still_routes_using_the_default():
    # The gap this closes: a router built from the DEFAULT table alone (no
    # operator classification_table at all) must still produce guidance for
    # every builtin category -- enabling the plane is never a silent no-op.
    r = Router(private_alias="local-model", knowledge_alias="knowledge-model",
               classification_table=DEFAULT_CLASSIFICATION_TABLE, knowledge_enabled=True)
    for category in ("hardware", "storage", "network", "container", "generic"):
        result = r.route_knowledge(category)
        assert result is not None
        _alias, prompt = result
        assert prompt == DEFAULT_CLASSIFICATION_TABLE[category]


def test_operator_table_entry_overrides_default_per_key_not_wholesale():
    # nuncio.config.build_router merges `{**DEFAULT, **operator}` -- simulate
    # that merge here at the Router level: an operator override for ONE
    # category must not erase the defaults for the others.
    operator_table = {"container": "an operator-authored, still generic override"}
    merged = {**DEFAULT_CLASSIFICATION_TABLE, **operator_table}
    r = Router(private_alias="local-model", knowledge_alias="knowledge-model",
               classification_table=merged, knowledge_enabled=True)
    assert r.route_knowledge("container") == ("knowledge-model", operator_table["container"])
    assert r.route_knowledge("storage") == ("knowledge-model", DEFAULT_CLASSIFICATION_TABLE["storage"])


# --- Phase C: knowledge_redundant_with_private -- a static (settings-time)
# fact the engine combines with the per-alert depth to decide whether the
# garnish is worth running at all (see Engine._garnish_with_knowledge). ---

def test_knowledge_redundant_with_private_defaults_false():
    r = make_router(knowledge_enabled=True)
    assert r.knowledge_redundant_with_private is False


def test_knowledge_redundant_with_private_is_settable():
    r = Router(private_alias="local-model", knowledge_alias="knowledge-model",
               classification_table=TABLE, knowledge_enabled=True,
               knowledge_redundant_with_private=True)
    assert r.knowledge_redundant_with_private is True
