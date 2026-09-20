"""Benchmark runner: evaluate detectors and calibrate field weights."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.cases import CASES
from manifold.analysis.calibration import FEATURE_KEYS, calibrate, calibrated_detector
from manifold.benchmark import evaluate, evaluate_report, taint_detector, verified_detector


def main() -> int:
    codes = [c.code for c in CASES]
    labels = [1 if c.vulnerable else 0 for c in CASES]

    print("== raw taint pass ==")
    print(evaluate_report(CASES, taint_detector))

    print("\n== Z3-verified taint pass ==")
    print(evaluate_report(CASES, verified_detector))

    # Calibrate weights over the cheap signals (leave-one-out for honesty).
    print("\n== calibrated field (leave-one-out) ==")
    weights, bias = calibrate(codes, labels)
    named = {k: round(w, 3) for k, w in zip(FEATURE_KEYS, weights)}
    print(f"  learned weights: {named}  bias={bias:.3f}")

    # Leave-one-out cross-validation of the calibrated detector.
    loo_tp = loo_fp = loo_fn = loo_tn = 0
    for i, case in enumerate(CASES):
        train_codes = codes[:i] + codes[i + 1 :]
        train_labels = labels[:i] + labels[i + 1 :]
        w, b = calibrate(train_codes, train_labels)
        pred = calibrated_detector(w, b)(case.code)
        truth = case.vulnerable
        if truth and pred:
            loo_tp += 1
        elif truth and not pred:
            loo_fn += 1
        elif not truth and pred:
            loo_fp += 1
        else:
            loo_tn += 1
    prec = loo_tp / (loo_tp + loo_fp) if (loo_tp + loo_fp) else 1.0
    rec = loo_tp / (loo_tp + loo_fn) if (loo_tp + loo_fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print(f"  LOO precision={prec:.3f} recall={rec:.3f} f1={f1:.3f}  "
          f"(TP={loo_tp} FP={loo_fp} FN={loo_fn} TN={loo_tn})")

    # Full set metrics for the calibrated detector (trained on all, for reporting).
    m = evaluate(CASES, calibrated_detector(weights, bias))
    print(f"  train-on-all metrics: {m}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
