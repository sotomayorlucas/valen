"""Tests for the Juliet corpus loader."""

from manifold.corpus import load_juliet


def test_load_juliet_labels_and_concatenates(tmp_path):
    tc = tmp_path / "src" / "testcases" / "CWE89_SQL_Injection"
    tc.mkdir(parents=True)
    (tc / "CWE89_X_81a.java").write_text("class A { }")
    (tc / "CWE89_X_81_bad.java").write_text("class Bad { }")
    (tc / "CWE89_X_81_goodG2B.java").write_text("class Good { }")

    cases = load_juliet(str(tmp_path), cwes=["CWE89"])
    labels = {c.name: c.vulnerable for c in cases}
    assert labels == {"CWE89_X_81_bad.java": True, "CWE89_X_81_goodG2B.java": False}
    # the flow source file is concatenated into each case
    assert all("class A" in c.code for c in cases)
