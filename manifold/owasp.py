"""OWASP Benchmark 1.2 runner.

Parses ``expectedresults-1.2.csv`` (test case -> category, real-vulnerability,
CWE), analyzes each Java test case with the Java SAST adapter, and reports
per-category plus overall precision / recall / F1.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .benchmark import Metrics
from .ingest.java import JavaIngest

# Categories driven by request properties rather than source code (the weak
# algorithm is chosen in the benchmark's .properties files); the source-based
# detector cannot see them.
_PROPERTY_CATEGORIES = {"crypto", "hash"}

_TAINT_CATEGORIES = {"sqli", "cmdi", "pathtraver", "xss", "ldapi", "xpathi", "trustbound"}


@dataclass
class TestCase:
    name: str
    category: str
    vulnerable: bool
    cwe: str


def load_expected(csv_path: str) -> List[TestCase]:
    cases: List[TestCase] = []
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            name, category, vuln, cwe = row[0], row[1], row[2].strip().lower() == "true", row[3]
            cases.append(TestCase(name=name, category=category, vulnerable=vuln, cwe=cwe))
    return cases


def _analyze(java_path: Path, cache: Dict[str, bool]) -> bool:
    key = java_path.name
    if key not in cache:
        try:
            code = java_path.read_text()
        except (OSError, UnicodeDecodeError):
            cache[key] = False
        else:
            cache[key] = bool(JavaIngest().analyze(code, path=key).findings)
    return cache[key]


def evaluate(
    testcode_dir: str,
    csv_path: str,
    categories: Optional[List[str]] = None,
) -> Dict[str, Metrics]:
    """Return per-category metrics plus an ``overall`` entry."""
    cases = load_expected(csv_path)
    testcode = Path(testcode_dir)
    cache: Dict[str, bool] = {}

    per_cat: Dict[str, Metrics] = {}
    included = 0

    for tc in cases:
        if categories is not None and tc.category not in categories:
            continue
        included += 1
        predicted = _analyze(testcode / f"{tc.name}.java", cache)
        m = per_cat.setdefault(tc.category, Metrics())
        if tc.vulnerable and predicted:
            m.tp += 1
        elif tc.vulnerable and not predicted:
            m.fn += 1
        elif not tc.vulnerable and predicted:
            m.fp += 1
        else:
            m.tn += 1

    overall = Metrics()
    for m in per_cat.values():
        overall.tp += m.tp
        overall.fp += m.fp
        overall.fn += m.fn
        overall.tn += m.tn
    per_cat["overall"] = overall
    return per_cat
