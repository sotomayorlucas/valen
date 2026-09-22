"""Solidity reentrancy: directed-homology (GLMY) + checks-effects-interactions.

Validates the reentrancy signal on the SmartBugs-curated corpus: ``dataset/
reentrancy`` as positives, the other categories as negatives. Reports three
signals and their confusion:

* **ordering** (primary): a low-level ``call``/``delegatecall`` *before* a state
  write (checks-effects-interactions violation);
* **GLMY** (topological): the reentrancy loop modeled as a directed 2-cycle
  ``f -> EXT -> f``, detected by directed path homology;
* **symmetrized**: undirected homology, which *collapses* the 2-cycle.

Usage:
    python benchmarks/run_solidity_glmy.py --smartbugs /path/to/smartbugs-curated
    # or let it clone to a cache dir if absent
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.math_core import topology  # noqa: E402
from valen.analysis.reentrancy import analyze  # noqa: E402

_NEG_CATS = ["access_control", "arithmetic", "bad_randomness", "denial_of_service",
             "front_running", "short_addresses", "time_manipulation",
             "unchecked_low_level_calls", "other"]

CACHE = Path.home() / ".cache" / "valen" / "smartbugs-curated"


def _clone(dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--depth", "1",
                    "https://github.com/smartbugs/smartbugs-curated.git", str(dest)],
                   check=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smartbugs", type=str, default="")
    args = ap.parse_args()

    sb = Path(args.smartbugs) if args.smartbugs else CACHE
    if not (sb / "dataset" / "reentrancy").exists():
        _clone(sb)

    dataset = sb / "dataset"
    positives = sorted((dataset / "reentrancy").glob("*.sol"))
    negatives = []
    for c in _NEG_CATS:
        negatives += sorted((dataset / c).glob("*.sol"))

    def pred(code):
        return bool(analyze(code)["findings"])

    def glmy_cycle(code):
        return topology(analyze(code)["cycle_graph"], "call")["directed_path"]["beta1"] > 0

    def und_cycle(code):
        return topology(analyze(code)["cycle_graph"], "call")["beta1"] > 0

    def confusion(pred_fn):
        tp = fp = fn = tn = 0
        for p in positives:
            if pred_fn(p.read_text()):
                tp += 1
            else:
                fn += 1
        for p in negatives:
            if pred_fn(p.read_text()):
                fp += 1
            else:
                tn += 1
        pr = tp / (tp + fp) if (tp + fp) else 0.0
        rc = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": pr, "recall": rc, "f1": f1}

    res = {
        "n_positives": len(positives),
        "n_negatives": len(negatives),
        "ordering": confusion(pred),
        "glmy": confusion(glmy_cycle),
        "symmetrized": confusion(und_cycle),
    }

    print(f"== Solidity reentrancy (SmartBugs-curated: {len(positives)} pos, "
          f"{len(negatives)} neg) ==")
    for name, c in res.items():
        if name in ("n_positives", "n_negatives"):
            continue
        print(f"  {name:<12} P={c['precision']:.3f} R={c['recall']:.3f} F1={c['f1']:.3f} "
              f"(TP={c['tp']} FP={c['fp']} FN={c['fn']})")

    out = ROOT / "benchmarks" / "solidity_glmy_results.json"
    out.write_text(json.dumps(res, indent=2))
    print(f"  results -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
