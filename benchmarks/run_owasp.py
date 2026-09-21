"""Run the OWASP Benchmark 1.2 evaluation.

Usage:
    python benchmarks/run_owasp.py \
        --testcode /path/to/src/main/java/org/owasp/benchmark/testcode \
        --csv /path/to/expectedresults-1.2.csv
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.owasp import _TAINT_CATEGORIES, evaluate, load_expected

_HEADER = f"{'category':<14}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'prec':>8}{'recall':>8}{'f1':>8}{'J':>8}"


def main() -> int:
    parser = argparse.ArgumentParser(description="OWASP Benchmark 1.2 evaluation.")
    parser.add_argument("--testcode", required=True, help="path to the testcode directory")
    parser.add_argument("--csv", required=True, help="path to expectedresults-1.2.csv")
    parser.add_argument("--verify", action="store_true", help="use the Z3 verifier as the arbiter")
    parser.add_argument("--interproc", action="store_true", help="use the interprocedural Java analyzer")
    args = parser.parse_args()

    if not Path(args.testcode).is_dir():
        print(f"error: {args.testcode} is not a directory", file=sys.stderr)
        return 1

    detector = None
    if args.verify:
        from manifold.analysis.java_verifier import verify_java

        def detector(code, _v=verify_java):
            return bool(_v(code))
    elif args.interproc:
        from manifold.ingest.java_interproc import JavaInterproceduralIngest

        _a = JavaInterproceduralIngest()
        detector = lambda code: bool(_a.analyze(code).findings)

    total = len(load_expected(args.csv))
    print(f"== OWASP Benchmark 1.2 ({total} test cases){' + Z3' if args.verify else ''} ==")
    print(_HEADER)

    for scope_name, cats in (("taint categories", _TAINT_CATEGORIES), ("all categories", None)):
        metrics = evaluate(args.testcode, args.csv, categories=cats, detector=detector)
        print(f"\n-- {scope_name} --")
        for cat, m in sorted(metrics.items()):
            if cat == "overall":
                continue
            j = m.recall - (m.fp / (m.fp + m.tn) if (m.fp + m.tn) else 0.0)
            print(f"{cat:<14}{m.tp:>5}{m.fp:>5}{m.fn:>5}{m.tn:>5}"
                  f"{m.precision:>8.3f}{m.recall:>8.3f}{m.f1:>8.3f}{j:>8.3f}")
        o = metrics["overall"]
        j = o.recall - (o.fp / (o.fp + o.tn) if (o.fp + o.tn) else 0.0)
        print(f"{'overall':<14}{o.tp:>5}{o.fp:>5}{o.fn:>5}{o.tn:>5}"
              f"{o.precision:>8.3f}{o.recall:>8.3f}{o.f1:>8.3f}{j:>8.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
