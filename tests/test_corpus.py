"""Tests for the external-corpus loader."""

from pathlib import Path

from valen.benchmark import evaluate
from valen.corpus import adapter_detector, load_corpus, load_directory

FIXTURES = Path(__file__).resolve().parent.parent / "benchmarks" / "fixtures"


def test_load_directory_labels_cases():
    cases = load_directory(str(FIXTURES))
    names = {c.name: c.vulnerable for c in cases}
    assert names == {"sqli.py": True, "ok.py": False}


def test_adapter_detector_on_fixture():
    cases = load_directory(str(FIXTURES))
    det = adapter_detector("python")
    m = evaluate(cases, det)
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 0, 0, 1)


def test_load_corpus_dispatch(tmp_path):
    # A manifest also works.
    (tmp_path / "vuln.py").write_text("def f(x):\n    return eval(x)\n")
    (tmp_path / "ok.py").write_text("def f(x):\n    return x + 1\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        '[{"file": "vuln.py", "vulnerable": true}, {"file": "ok.py", "vulnerable": false}]'
    )
    cases = load_corpus(str(manifest))
    assert len(cases) == 2
    assert {c.vulnerable for c in cases} == {True, False}
