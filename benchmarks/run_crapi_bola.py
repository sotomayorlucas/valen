"""Real-data BOLA/IDOR/BFLA evaluation on OWASP crAPI.

Runs the API-level object-level-authorization detector against the *real*
crAPI OpenAPI spec (40 endpoints), with ground-truth labels transcribed from the
official challenge documentation, and reports the confusion plus the key
contrast: the "is it authenticated?" (missing-security-scheme) check cannot see
BOLA, because every BOLA endpoint *is* authenticated.

Writes benchmarks/crapi_bola_results.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.api_bola import api_bola_candidates  # noqa: E402

SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"
LABELS = ROOT / "examples" / "api" / "crapi_bola_labels.json"


def _key(method, path):
    return f"{method} {path}"


def main() -> int:
    spec = json.loads(SPEC.read_text())
    labels = json.loads(LABELS.read_text())
    vulnerable = set(labels["vulnerable"])

    # enumerate all operations
    ops = []
    for url, methods in spec["paths"].items():
        for method, op in methods.items():
            if isinstance(op, dict):
                ops.append((method.upper(), url, op))

    flagged = set()
    for method, path, _ in api_bola_candidates(spec):
        flagged.add(_key(method, path))

    tp = fp = fn = tn = 0
    rows = []
    for method, path, op in ops:
        k = _key(method, path)
        vuln = k in vulnerable
        pred = k in flagged
        tp += pred and vuln
        fp += pred and not vuln
        fn += (not pred) and vuln
        tn += (not pred) and not vuln
        # "authenticated" = has a security scheme (for the contrast)
        authenticated = bool(op.get("security"))
        rows.append({"key": k, "vulnerable": vuln, "predicted": pred,
                     "authenticated": authenticated})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # contrast: how many true BOLA endpoints are authenticated (hence invisible
    # to a missing-auth-scheme check) vs missing a scheme?
    vuln_auth = sum(1 for r in rows if r["vulnerable"] and r["authenticated"])
    n_vuln = sum(1 for r in rows if r["vulnerable"])

    print(f"== crAPI object-level authorization (n={len(rows)} operations, "
          f"{n_vuln} documented BOLA/BFLA) ==")
    for r in rows:
        if r["vulnerable"] or r["predicted"]:
            mark = "" if r["predicted"] == r["vulnerable"] else "  <-- mismatch"
            print(f"  {r['key']:<52} vuln={int(r['vulnerable'])} pred={int(r['predicted'])} "
                  f"auth={int(r['authenticated'])}{mark}")
    print(f"\n  TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  precision={precision:.3f} recall={recall:.3f} F1={f1:.3f}")
    print(f"\n  contrast: {vuln_auth}/{n_vuln} BOLA endpoints ARE authenticated "
          f"-> a missing-security-scheme check scores recall 0 on BOLA.")

    out = ROOT / "benchmarks" / "crapi_bola_results.json"
    out.write_text(json.dumps({
        "n": len(rows), "n_vulnerable": n_vuln,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "vulnerable_authenticated": vuln_auth,
        "false_positives": [r["key"] for r in rows if r["predicted"] and not r["vulnerable"]],
        "false_negatives": [r["key"] for r in rows if r["vulnerable"] and not r["predicted"]],
        "rows": rows,
    }, indent=2))
    print(f"  results -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
