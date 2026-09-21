"""Ordered red-team attack plan: MITRE-tagged, evidence-backed.

Combines VALEN's structural findings into a kill-chain ordered by tactic:
Discovery (IAM Fiedler bridges), Privilege Escalation (IAM escalation chains,
Z3-confirmed), and Collection (BOLA/IDOR PoCs over crAPI). Writes
benchmarks/attack_plan.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.trust import fiedler_boundary, privilege_bridges  # noqa: E402
from valen.ingest.iam import IAMIgest  # noqa: E402
from valen.redteam.attack_paths import tagged_chains  # noqa: E402
from valen.redteam.mitre import PHASE_ORDER  # noqa: E402
from valen.redteam.poc import generate_pocs  # noqa: E402

SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"
LABELS = ROOT / "examples" / "api" / "crapi_bola_labels.json"
IAM = ROOT / "examples" / "iam" / "demo.json"


def main() -> int:
    # -- Discovery: IAM trust topology -------------------------------
    iam_graph = IAMIgest().analyze(IAM.read_text()).graph
    bridges = privilege_bridges(iam_graph)
    boundary = [b[0] for b in fiedler_boundary(iam_graph)]

    # -- Privilege escalation: IAM chains ----------------------------
    chains = tagged_chains(iam_graph, ["public-api"], ["secrets-bucket", "admin-role"])

    # -- Collection: BOLA PoCs over crAPI ----------------------------
    spec = json.loads(SPEC.read_text())
    labels = json.loads(LABELS.read_text())
    pocs = generate_pocs(spec, labels)

    steps = []

    bridge_desc = ", ".join(f"{b['src_label']}->{b['dst_label']}" for b in bridges[:3])
    steps.append({
        "phase": "Discovery", "tactic_id": "TA0007", "tactic": "Discovery",
        "title": "Map the trust topology (IAM)",
        "detail": f"Fiedler boundary: {boundary}; privilege bridges: {bridge_desc}",
    })

    for c in chains:
        steps.append({
            "phase": "Privilege Escalation", "tactic_id": "TA0004",
            "tactic": "Privilege Escalation",
            "title": f"Escalate {c['entry']} -> {c['target']}",
            "chain": [f"{s['from']} -[{s['relation']}]-> {s['to']}" for s in c["steps"]],
            "z3_reachable": c["z3"]["reachable"],
            "z3_witness": c["z3"]["escalation_witness"],
        })

    for p in pocs:
        steps.append({
            "phase": "Collection", "tactic_id": "TA0009", "tactic": "Collection",
            "title": f"Read victim resource via {p['method']} {p['path']}",
            "poc": p["poc"],
        })

    steps.sort(key=lambda s: PHASE_ORDER.get(s["tactic_id"], 99))

    print(f"== VALEN ordered attack plan ({len(steps)} steps) ==")
    for s in steps:
        print(f"  [{s['tactic_id']} {s['phase']:<20}] {s['title']}")

    out = ROOT / "benchmarks" / "attack_plan.json"
    out.write_text(json.dumps({"steps": steps}, indent=2))
    print(f"  plan -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
