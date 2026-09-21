"""Red-team assistance over crAPI: generate a PoC per BOLA/IDOR endpoint.

Turns the structural findings (9 documented BOLA/BFLA endpoints) into runnable
``requests`` proof-of-concepts. With ``--base-url`` it also replays the first PoC
against a live target to confirm impact.

Writes benchmarks/redteam_pocs.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.redteam.live import LiveValidator  # noqa: E402
from valen.redteam.poc import generate_pocs  # noqa: E402

SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"
LABELS = ROOT / "examples" / "api" / "crapi_bola_labels.json"

# Leak hints transcribed from the crAPI challenge documentation where a concrete
# leaked field is named; empty elsewhere (the red team inspects the body).
LEAK_HINTS = {
    "GET /identity/api/v2/vehicle/{vehicleId}/location": "full_name",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", type=str, default="", help="live target (default: PoCs only)")
    ap.add_argument("--token", type=str, default="", help="attacker bearer token")
    ap.add_argument("--victim", type=str, default="", help="victim object id")
    args = ap.parse_args()

    spec = json.loads(SPEC.read_text())
    labels = json.loads(LABELS.read_text())
    pocs = generate_pocs(spec, labels, leak_hints=LEAK_HINTS)

    print(f"== VALEN red-team assistance: {len(pocs)} BOLA/IDOR PoCs (crAPI) ==")
    for p in pocs:
        print(f"  [{p['method']:6}] {p['path']}" + (f"  leak_hint={p['leak_hint']!r}" if p["leak_hint"] else ""))

    out = ROOT / "benchmarks" / "redteam_pocs.json"
    out.write_text(json.dumps({"n": len(pocs), "pocs": pocs}, indent=2))
    print(f"  PoCs -> {out.relative_to(ROOT)}")

    if args.base_url:
        if not (args.token and args.victim):
            print("  --token and --victim required to validate against a live target")
            return 1
        v = LiveValidator(args.base_url)
        first = pocs[0]
        res = v.validate(first, args.victim, args.token)
        print(f"  live validation of {first['method']} {first['path']}: "
              f"status={res['status']} leaked={res['leaked']}")
        print(f"  evidence: {res['evidence']!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
