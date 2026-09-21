"""Run the Java SAST adapter on the Juliet Java test suite.

Usage:
    python benchmarks/run_juliet.py --root /path/to/juliet-test-suite [--cwes CWE89,CWE78]
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.benchmark import Metrics
from valen.corpus import load_juliet
from valen.ingest.java import JavaIngest


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--cwes", default="CWE89,CWE78,CWE80,CWE81,CWE90,CWE643,CWE22,CWE501")
    ap.add_argument("--interproc", action="store_true", help="use the interprocedural Java analyzer")
    ap.add_argument("--cs", action="store_true", help="context-sensitive (with --interproc)")
    args = ap.parse_args()

    if args.interproc:
        from valen.ingest.java_interproc import JavaInterproceduralIngest

        _base = JavaInterproceduralIngest()

        class _CS:
            def analyze(self, code, path="<java>"):
                return _base.analyze(code, path=path, context_sensitive=True)

        analyzer = _CS() if args.cs else _base
    else:
        analyzer = JavaIngest()

    cwes = [c.strip() for c in args.cwes.split(",") if c.strip()]
    cases = load_juliet(args.root, cwes=cwes)
    print(f"== Juliet Java ({'interprocedural' if args.interproc else 'intraprocedural'}): "
          f"{len(cases)} test cases, CWEs={cwes} ==")
    print(f"{'CWE':<8}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'prec':>8}{'recall':>8}{'f1':>8}")

    per = defaultdict(Metrics)
    for case in cases:
        cwe = case.name.split("_")[0]
        pred = bool(analyzer.analyze(case.code, path=case.name).findings)
        m = per[cwe]
        if case.vulnerable and pred:
            m.tp += 1
        elif case.vulnerable and not pred:
            m.fn += 1
        elif not case.vulnerable and pred:
            m.fp += 1
        else:
            m.tn += 1

    total = Metrics()
    for cwe in sorted(per):
        m = per[cwe]
        print(f"{cwe:<8}{m.tp:>5}{m.fp:>5}{m.fn:>5}{m.tn:>5}{m.precision:>8.3f}{m.recall:>8.3f}{m.f1:>8.3f}")
        total.tp += m.tp; total.fp += m.fp; total.fn += m.fn; total.tn += m.tn
    print(f"{'overall':<8}{total.tp:>5}{total.fp:>5}{total.fn:>5}{total.tn:>5}"
          f"{total.precision:>8.3f}{total.recall:>8.3f}{total.f1:>8.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
