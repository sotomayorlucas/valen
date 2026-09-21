"""BOLA / IDOR + missing-authorization evaluation on a curated micro-corpus.

This is the *trust & logic* experiment: classic taint analysis is structurally
blind to BOLA/IDOR (the object selector is a clean, cast value) and to missing
authorization (the data may even be tainted, but the bug is the absent privilege
boundary). MANIFOLD's structural signal --- an ungated, user-controlled resource
access --- is what surfaces them.

The corpus is intentionally SMALL and curated; we report precision/recall as an
honest feasibility signal, not a production benchmark.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from manifold.analysis.authorization import bola_idor_candidates  # noqa: E402
from manifold.ingest.python import PythonIngest  # noqa: E402

CORPUS = ROOT / "examples" / "python" / "bola"

# filename -> is_vulnerable
LABELS = {
    "idor_vuln.py": True,
    "idor_fixed_gate.py": False,
    "idor_fixed_ownership.py": False,
    "cwe862_vuln.py": True,
    "cwe862_fixed.py": False,
    "benign.py": False,
}


def main() -> int:
    tp = fp = fn = tn = 0
    rows = []
    for name, vulnerable in sorted(LABELS.items()):
        path = CORPUS / name
        # fresh ingest per file: the adapter keeps per-analysis state
        result = PythonIngest().analyze(path.read_text(), path=name)
        cands = bola_idor_candidates(result.graph)
        predicted = len(cands) > 0
        if predicted and vulnerable:
            tp += 1
        elif predicted and not vulnerable:
            fp += 1
        elif not predicted and vulnerable:
            fn += 1
        else:
            tn += 1
        rows.append({
            "file": name,
            "vulnerable": vulnerable,
            "predicted": predicted,
            "n_candidates": len(cands),
            "categories": sorted({c.category for c in cands}),
        })

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print("== BOLA / IDOR + missing-authorization (curated micro-corpus) ==")
    for r in rows:
        print(f"  {r['file']:<28} vuln={int(r['vulnerable'])} pred={int(r['predicted'])} "
              f"cands={r['n_candidates']} {r['categories']}")
    print(f"\n  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  precision={precision:.3f} recall={recall:.3f} F1={f1:.3f} "
          f"(n={len(LABELS)} curated cases)")

    out = ROOT / "benchmarks" / "bola_results.json"
    out.write_text(json.dumps(
        {"precision": precision, "recall": recall, "f1": f1,
         "tp": tp, "fp": fp, "fn": fn, "tn": tn,
         "n": len(LABELS), "rows": rows}, indent=2))
    print(f"  results -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
