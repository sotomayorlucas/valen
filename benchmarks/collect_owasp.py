"""Collect the OWASP Benchmark metrics into `benchmarks/owasp_results.json`.

Usage:
    python benchmarks/collect_owasp.py --testcode <dir> --csv <csv> [--verify]

The adapter results are fast; `--verify` adds the Z3-verified taint categories.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.owasp import _TAINT_CATEGORIES, evaluate


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--testcode", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--verify", action="store_true", help="also collect the Z3-verified taint metrics")
    args = ap.parse_args()

    out: dict = {"testcode": args.testcode, "csv": args.csv}
    adapter = evaluate(args.testcode, args.csv)
    out["adapter_all"] = {k: m.as_dict() for k, m in adapter.items()}
    taint = evaluate(args.testcode, args.csv, categories=_TAINT_CATEGORIES)
    out["adapter_taint"] = {k: m.as_dict() for k, m in taint.items()}

    if args.verify:
        from valen.analysis.java_verifier import verify_java

        z3 = evaluate(args.testcode, args.csv, categories=_TAINT_CATEGORIES, detector=lambda c: bool(verify_java(c)))
        out["z3_taint"] = {k: m.as_dict() for k, m in z3.items()}

    path = ROOT / "benchmarks" / "owasp_results.json"
    path.write_text(json.dumps(out, indent=2))
    print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
