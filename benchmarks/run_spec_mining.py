"""Specification-mining ablation (small): can the LLM mine the right invariant?

The neuro-symbolic split claims the LLM *proposes* structured specs and Z3
*discharges* them. This measures only the *proposal* half on a small curated set:
given code, does the LLM state the security precondition (invariant) the code
must enforce? Scoring is a token-overlap match against a hand-written ground
truth; the hallucination rate is the fraction of answers with no overlap.

This is a small, honest feasibility signal (n=8), not a benchmark.

Usage (online needs the LiteLLM proxy):
    set -a; . ~/litellm/.env; set +a
    VALEN_LLM_MODEL=openai/flash VALEN_LLM_BASE_URL=http://127.0.0.1:4000 \
    VALEN_LLM_API_KEY=$LITELLM_MASTER_KEY python benchmarks/run_spec_mining.py
Writes benchmarks/spec_mining_results.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.llm import LLMClient

# code -> (ground_truth_precondition, key tokens)
CASES = {
    "owner_check": (
        "def get_order(db, request):\n    oid = int(request.args.get('id'))\n"
        "    return db.execute('SELECT * FROM orders WHERE id = ?', (oid,)).fetchall()",
        "the object must belong to the caller (ownership / authorization check)",
        {"owner", "ownership", "belong", "authoriz"},
    ),
    "balance_check": (
        "def transfer(db, src, dst, amount):\n"
        "    db.execute('UPDATE acct SET bal = bal - ? WHERE id = ?', (amount, src))\n"
        "    db.execute('UPDATE acct SET bal = bal + ? WHERE id = ?', (amount, dst))",
        "the source balance must be sufficient (amount >= 0, no overdraft)",
        {"balance", "sufficient", "overdraft", "amount"},
    ),
    "int_validation": (
        "def lookup(db, request):\n    uid = request.args.get('id')\n"
        "    return db.execute('SELECT * FROM u WHERE id = ' + uid).fetchall()",
        "the input must be validated / sanitized before use in SQL",
        {"valid", "sanitiz", "escape", "parameter"},
    ),
    "auth_gate": (
        "def delete_user(db, request):\n    uid = request.args.get('uid')\n"
        "    db.execute('DELETE FROM users WHERE id = ?', (uid,))",
        "the caller must be authenticated and authorized (admin)",
        {"authentic", "authoriz", "admin", "permission"},
    ),
    "nonce_check": (
        "def redeem(code):\n    if lookup(code):\n        return grant(code)",
        "the code must be single-use (unused / not already redeemed)",
        {"unused", "single-use", "redeem", "replay", "once"},
    ),
    "sanitize_shell": (
        "import os\n\ndef ping(request):\n    os.system('ping ' + request.args.get('host'))",
        "the command argument must be validated / quoted before shell execution",
        {"valid", "quote", "sanitiz", "escape"},
    ),
    "deser_safe": (
        "import pickle\n\ndef load(request):\n    return pickle.loads(request.data)",
        "the serialized data must be trusted / authenticated before deserialization",
        {"trust", "authentic", "sign", "untrusted"},
    ),
    "path_bound": (
        "import os\n\ndef read(request):\n    return open('/srv/' + request.args.get('f')).read()",
        "the path must be confined to a safe directory (no traversal)",
        {"confine", "director", "traversal", "safe", "root"},
    ),
}

PROMPT = (
    "You are a security reviewer. Given the code, state in ONE short sentence the "
    "single most important security precondition (invariant) this code must enforce "
    "to be safe. Answer only the sentence."
)


def _score(llm_answer: str, tokens: set) -> float:
    lowered = llm_answer.lower()
    hit = sum(1 for t in tokens if t in lowered)
    return hit / len(tokens) if tokens else 0.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=str, default="")
    args = ap.parse_args()

    live = bool(os.environ.get("VALEN_LLM_MODEL") and os.environ.get("VALEN_LLM_BASE_URL"))
    client = LLMClient()

    rows = []
    for name, (code, truth, tokens) in CASES.items():
        answer = client.complete([
            {"role": "system", "content": PROMPT},
            {"role": "user", "content": code},
        ])
        if answer is None:
            answer = ""
        score = _score(answer, tokens)
        rows.append({"name": name, "answer": answer, "truth": truth,
                     "score": score, "hallucinated": score == 0.0})

    n = len(rows)
    mean_score = sum(r["score"] for r in rows) / n if n else 0.0
    halluc = sum(1 for r in rows if r["hallucinated"]) / n if n else 0.0

    summary = {"live": live, "n": n, "mean_token_recall": mean_score,
               "hallucination_rate": halluc}
    print(f"LLM configured: {live}")
    for r in rows:
        print(f"  {r['name']:<18} recall={r['score']:.2f} hallucinated={r['hallucinated']}  {r['answer'][:70]}")
    print(f"\n  mean token recall = {mean_score:.3f}   hallucination rate = {halluc:.3f}  (n={n})")

    out = Path(args.out) if args.out else ROOT / "benchmarks" / "spec_mining_results.json"
    out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    print(f"results -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
