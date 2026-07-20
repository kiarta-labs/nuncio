"""Replay-harness grading.

Makes the qualitative bar testable: an enrichment should CITE the correct bundle
evidence for its stated cause, and must NOT FABRICATE an identifier that wasn't
in the input. Used by the live replay runner over a seed corpus of real
incidents (auth failures, resource-correlation outages, mount races, and the
like) and as a regression suite on prompt/model changes.
"""


def grade(text, must_cite, forbidden, cite_threshold=0.8):
    """Grade one enrichment against a per-case rubric.

    - must_cite:  substrings that SHOULD appear (correct evidence) — case-insensitive.
    - forbidden:  identifiers that must NOT appear (hallucinations) — case-insensitive.
    Returns {cite_score, fabrications, ok}.
    """
    low = text.lower()
    if must_cite:
        cited = sum(1 for kw in must_cite if kw.lower() in low)
        cite_score = cited / len(must_cite)
    else:
        cite_score = 1.0
    fabrications = [f for f in forbidden if f.lower() in low]
    ok = cite_score >= cite_threshold and not fabrications
    return {"cite_score": cite_score, "fabrications": fabrications, "ok": ok}
