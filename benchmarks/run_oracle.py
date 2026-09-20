"""Prioritization-oracle experiment on OWASP Benchmark 1.2.

Usage:
    python benchmarks/run_oracle.py --testcode <dir> --csv <expectedresults.csv>
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.oracle import (
    SIGNALS,
    analyze_case,
    cost_curve,
    evaluate_cached,
    evaluate_signal_cached,
    signal_aucs,
)
from manifold.owasp import _TAINT_CATEGORIES, load_expected

import pickle


def _load_cache(testcode, csv, cache_path):
    """Analyze the corpus once and persist the per-case candidate cache."""
    if cache_path.exists():
        with cache_path.open("rb") as f:
            return pickle.load(f)
    cache = []
    for tc in load_expected(csv):
        if tc.category not in _TAINT_CATEGORIES or not tc.vulnerable:
            continue
        code = (testcode / f"{tc.name}.java").read_text()
        cache.append((analyze_case(code), tc.category))
    with cache_path.open("wb") as f:
        pickle.dump(cache, f)
    return cache


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--testcode", required=True)
    ap.add_argument("--csv", required=True)
    ap.add_argument("--budget", type=int, default=8)
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--refresh", action="store_true", help="ignore the analysis cache")
    args = ap.parse_args()

    testcode = Path(args.testcode)
    cache_path = ROOT / "benchmarks" / "oracle_cache.pkl"
    if args.refresh and cache_path.exists():
        cache_path.unlink()
    cache = _load_cache(testcode, args.csv, cache_path)

    n = len(cache)
    print(f"== prioritization oracle: {n} vulnerable taint cases ==")
    print(f"{'method':<8}{'MRR':>8}{'R@1':>8}{'mean_rank':>11}{'NDCG@5':>9}")
    results: dict = {}

    for method in ("dfs", "taint", "field"):
        m = evaluate_cached(cache, method)
        results[method] = m.as_dict()
        print(f"{method:<8}{m.mrr:>8.3f}{m.recall_at_1:>8.3f}{m.mean_rank:>11.3f}{m.ndcg_at_5:>9.3f}")

    mrrs, r1s, ndcgs = [], [], []
    for seed in range(args.seeds):
        m = evaluate_cached(cache, "random", seed)
        mrrs.append(m.mrr)
        r1s.append(m.recall_at_1)
        ndcgs.append(m.ndcg_at_5)
    ci = lambda xs: 1.96 * statistics.pstdev(xs) / (len(xs) ** 0.5)
    results["random"] = {
        "mrr": statistics.mean(mrrs), "mrr_ci": ci(mrrs),
        "recall@1": statistics.mean(r1s), "recall@1_ci": ci(r1s),
        "ndcg@5": statistics.mean(ndcgs), "ndcg@5_ci": ci(ndcgs),
    }
    print(f"{'random':<8}{statistics.mean(mrrs):>8.3f}{statistics.mean(r1s):>8.3f}"
          f"{'':>11}{statistics.mean(ndcgs):>9.3f}  (+/-{ci(mrrs):.3f} MRR)")

    print("\n== per-signal ranking ablation (MRR) ==")
    signal_mrr = {}
    for signal in SIGNALS:
        m = evaluate_signal_cached(cache, signal)
        signal_mrr[signal] = m.as_dict()
        print(f"  {signal:<12} MRR={m.mrr:.3f}  R@1={m.recall_at_1:.3f}")

    print("\n== per-signal AUC (candidate is the ground-truth sink) ==")
    aucs = signal_aucs(cache)
    for signal, a in aucs.items():
        print(f"  {signal:<12} AUC={a['auc']:.3f}  CI95={a['ci95']}")

    curves = {}
    for method in ("dfs", "taint", "field"):
        curves[method] = cost_curve(evaluate_cached(cache, method).ranks, args.budget)
    rand_curve = []
    for b in range(1, args.budget + 1):
        vals = [cost_curve(evaluate_cached(cache, "random", s).ranks, b)[-1] for s in range(args.seeds)]
        rand_curve.append(statistics.mean(vals))
    curves["random"] = rand_curve

    print("\n== cost curve (cumulative recall vs #queries) ==")
    print("budget " + " ".join(f"{b:>6}" for b in range(1, args.budget + 1)))
    for method, curve in curves.items():
        print(f"{method:<7}" + " ".join(f"{v:>6.3f}" for v in curve))

    out = ROOT / "benchmarks" / "oracle_results.json"
    out.write_text(json.dumps(
        {"metrics": results, "signals_mrr": signal_mrr, "signals_auc": aucs,
         "curves": curves, "n": n}, indent=2))
    print(f"\nresults -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
