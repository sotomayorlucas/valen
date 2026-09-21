"""External-corpus loader: turn a labeled corpus into benchmark cases.

Supports two conventions so the harness can be pointed at a local copy of a
benchmark (OWASP Benchmark's source tree, a SARD export, or any directory of
labeled files):

* a JSON **manifest**: ``[{"file": "path", "vulnerable": true, "cwe": "CWE-89"}]``
* a **directory** with ``vulnerable``/``bad`` and ``safe``/``good`` subfolders.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from .benchmark import Case, Detector
from .ingest import analyze

_VULN_DIRS = ("vulnerable", "bad")
_SAFE_DIRS = ("safe", "good")


def adapter_detector(adapter: str) -> Detector:
    """A ``code -> bool`` detector over the given ingest adapter (findings != empty)."""

    def detector(code: str) -> bool:
        try:
            result = analyze(code, path="<case>", adapter=adapter)
        except Exception:
            return False
        return bool(result.findings)

    return detector


def case_from_file(path: str, vulnerable: bool) -> Case:
    p = Path(path)
    return Case(name=p.name, code=p.read_text(), vulnerable=vulnerable)


def load_manifest(manifest_path: str) -> List[Case]:
    """Load cases from a JSON manifest of ``{file, vulnerable, name?, cwe?}``."""
    data = json.loads(Path(manifest_path).read_text())
    base = Path(manifest_path).parent
    cases: List[Case] = []
    for entry in data:
        fp = entry["file"]
        if not Path(fp).is_absolute():
            fp = str(base / fp)
        name = entry.get("name") or Path(fp).name
        cases.append(
            Case(name=name, code=Path(fp).read_text(), vulnerable=bool(entry["vulnerable"]))
        )
    return cases


def load_directory(root: str) -> List[Case]:
    """Load cases from ``<root>/vulnerable|bad`` and ``<root>/safe|good``."""
    root = Path(root)
    cases: List[Case] = []
    for label in _VULN_DIRS:
        d = root / label
        if d.is_dir():
            cases.extend(case_from_file(str(f), True) for f in sorted(d.iterdir()) if f.is_file())
    for label in _SAFE_DIRS:
        d = root / label
        if d.is_dir():
            cases.extend(case_from_file(str(f), False) for f in sorted(d.iterdir()) if f.is_file())
    return cases


def load_corpus(path: str) -> List[Case]:
    """Dispatch on the corpus layout: a JSON manifest or a directory."""
    p = Path(path)
    if p.is_dir():
        return load_directory(path)
    return load_manifest(path)


def load_juliet(root: str, cwes: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Case]:
    """Load the Juliet Java test suite (find-sec-bugs/juliet-test-suite layout).

    Each ``*_bad.java`` / ``*_good*.java`` test case is concatenated with its
    sibling flow-variant files (``_a``, ``_base``, ...) so the source context is
    present. ``bad`` = vulnerable, ``good*`` = safe.
    """
    root_path = Path(root) / "src" / "testcases"
    if not root_path.is_dir():
        root_path = Path(root)
    cases: List[Case] = []
    for cwe_dir in sorted(root_path.glob("CWE*")):
        cwe = cwe_dir.name.split("_")[0]
        if cwes and cwe not in cwes:
            continue
        dirs = [cwe_dir] + [d for d in cwe_dir.iterdir() if d.is_dir()]
        for variant_dir in sorted(dirs):
            files = {f.name: f for f in variant_dir.glob("*.java")}
            if not any(k.endswith("_bad.java") or "_good" in k for k in files):
                continue
            for fname, fpath in files.items():
                stem = fname[:-5]  # strip .java
                is_bad = stem.endswith("_bad")
                is_good = "_good" in stem
                if not (is_bad or is_good):
                    continue
                prefix = stem[:-4] if is_bad else stem.split("_good", 1)[0]
                parts = [p.read_text() for k, p in files.items() if k.startswith(prefix)]
                cases.append(Case(name=fname, code="\n".join(parts), vulnerable=is_bad))
                if limit and len(cases) >= limit:
                    return cases
    return cases
