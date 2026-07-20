"""Replay-harness grading. The qualitative bar, made testable:
an enrichment must cite the correct bundle evidence and must NOT fabricate an
identifier that wasn't in the input."""
from nuncio.replay import grade


def test_grade_counts_cited_evidence():
    text = "SUMMARY: the 401 was caused by the «REDACTED:env» credential. SEVERITY: urgent."
    r = grade(text, must_cite=["401", "REDACTED:env"], forbidden=[])
    assert r["cite_score"] == 1.0


def test_grade_partial_citation():
    r = grade("only mentions the 401 here", must_cite=["401", "GPF"], forbidden=[])
    assert r["cite_score"] == 0.5


def test_grade_flags_fabricated_identifiers():
    text = "SUMMARY: the database on host webserver-07 at 10.99.99.99 failed."
    r = grade(text, must_cite=[], forbidden=["webserver-07", "10.99.99.99"])
    assert set(r["fabrications"]) == {"webserver-07", "10.99.99.99"}
    assert not r["ok"]


def test_grade_ok_when_cited_and_no_fabrication():
    text = "SUMMARY: infisical-postgres exhausted AuxiliaryProcs; correlates with the GPF storm."
    r = grade(text, must_cite=["AuxiliaryProcs", "GPF"], forbidden=["mysql", "webserver-07"])
    assert r["ok"]
    assert r["cite_score"] == 1.0
    assert r["fabrications"] == []
