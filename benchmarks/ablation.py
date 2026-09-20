"""Ablation of the Java adapter improvements (branch-join, XSS writer restriction).

Usage:
    python benchmarks/ablation.py --testcode <dir> --csv <csv>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.ingest import java as J
from manifold.owasp import _TAINT_CATEGORIES, evaluate


def run(testcode, csv):
    m = evaluate(testcode, csv, categories=_TAINT_CATEGORIES)["overall"]
    return m.as_dict()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--testcode", required=True)
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()

    results: dict = {}

    # baseline: branch-join disabled + XSS restriction disabled
    seq = lambda self, node, graph, env, findings, path: [self._walk(c, graph, env, findings, path) for c in node.named_children]
    orig_if = J.JavaIngest._if_statement
    orig_xss = J.JavaIngest._is_response_writer
    J.JavaIngest._if_statement = seq
    J.JavaIngest._is_response_writer = lambda self, obj: True
    results["baseline"] = run(args.testcode, args.csv)

    # + branch-join, receiver/state taint, sink coverage (XSS restriction off)
    J.JavaIngest._if_statement = orig_if
    results["+branch_join_state_sinks"] = run(args.testcode, args.csv)

    # + XSS response-writer restriction (full)
    J.JavaIngest._is_response_writer = orig_xss
    results["full"] = run(args.testcode, args.csv)

    # full without branch-join
    J.JavaIngest._if_statement = seq
    results["without_branch_join"] = run(args.testcode, args.csv)
    J.JavaIngest._if_statement = orig_if

    path = ROOT / "benchmarks" / "ablation_results.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"wrote {path.relative_to(ROOT)}")
    for k, v in results.items():
        print(f"  {k:<28} P={v['precision']:.3f} R={v['recall']:.3f} F1={v['f1']:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
