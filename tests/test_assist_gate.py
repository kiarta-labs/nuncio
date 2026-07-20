"""Structural gate: `redactor.ScrubbedPayload` may only ever be constructed
inside `nuncio/redactor.py` -- the ONLY way text can reach the assist plane's
LLM call is by passing through `scrub_for_assist_plane()` first. Enforced
here with a grep across the whole package, not just by convention.
"""
import pathlib

import pytest

from nuncio.assist import AssistClient


def test_scrubbedpayload_construction_only_in_redactor():
    root = pathlib.Path(__file__).resolve().parent.parent / "nuncio"
    hits = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "ScrubbedPayload(" in text:
            hits.append(path.relative_to(root).as_posix())
    assert hits == ["redactor.py"]


def test_assist_client_insight_requires_scrubbed_payload():
    client = AssistClient(None)
    with pytest.raises(TypeError):
        client.insight("just a plain string, not a ScrubbedPayload")


def test_assist_client_insight_rejects_a_plain_dict_too():
    client = AssistClient(None)
    with pytest.raises(TypeError):
        client.insight({"text": "not scrubbed"})
