"""Ordered red-team attack plan: MITRE-tagged, evidence-backed.

Combines every VALEN source into a kill-chain ordered by tactic:
Discovery (network map + IAM trust bridges), Execution/Credential Access
(nuclei-verified findings), Privilege Escalation (IAM escalation chains,
Z3-confirmed), and Collection (BOLA/IDOR PoCs over crAPI). Writes
benchmarks/attack_plan.json.

    python benchmarks/run_attack_plan.py
    python benchmarks/run_attack_plan.py --nuclei /path/scan.jsonl --network /path/map.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.trust import fiedler_boundary, privilege_bridges  # noqa: E402
from valen.ingest.iam import IAMIgest  # noqa: E402
from valen.redteam.attack_paths import tagged_chains  # noqa: E402
from valen.redteam.mitre import PHASE_ORDER  # noqa: E402
from valen.redteam.nuclei import parse_nuclei_json, to_plan_steps  # noqa: E402
from valen.redteam.poc import generate_pocs  # noqa: E402
from valen.redteam.recon import network_topology_graph, parse_nmap_xml  # noqa: E402

SPEC = ROOT / "examples" / "api" / "crapi-openapi-spec.json"
LABELS = ROOT / "examples" / "api" / "crapi_bola_labels.json"
IAM = ROOT / "examples" / "iam" / "demo.json"
NUCLEI = ROOT / "examples" / "recon" / "nuclei.jsonl"
NMAP = ROOT / "examples" / "recon" / "nmap.xml"
GATEWAY = "10.0.0.1"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nuclei", type=str, default=str(NUCLEI))
    ap.add_argument("--nmap", type=str, default=str(NMAP))
    ap.add_argument("--gateway", type=str, default=GATEWAY)
    args = ap.parse_args()

    steps: list = []

    # -- Discovery: network map + IAM trust topology ------------------
    if Path(args.nmap).exists():
        hosts = parse_nmap_xml(Path(args.nmap).read_text())
        net = network_topology_graph(hosts, args.gateway)
        nb = privilege_bridges(net)
        nb_desc = ", ".join(f"{b['src_label']}<->{b['dst_label']}" for b in nb[:4])
        steps.append({
            "phase": "Discovery", "tactic_id": "TA0007", "tactic": "Discovery",
            "title": f"Map the network ({len(hosts)} hosts, gateway {args.gateway})",
            "detail": f"pivot/route bridges: {nb_desc}",
        })

    iam_graph = IAMIgest().analyze(IAM.read_text()).graph
    bridges = privilege_bridges(iam_graph)
    boundary = [b[0] for b in fiedler_boundary(iam_graph)]
    bdesc = ", ".join(f"{b['src_label']}->{b['dst_label']}" for b in bridges[:3])
    steps.append({
        "phase": "Discovery", "tactic_id": "TA0007", "tactic": "Discovery",
        "title": "Map the trust topology (IAM)",
        "detail": f"Fiedler boundary: {boundary}; privilege bridges: {bdesc}",
    })

    # -- Execution / Credential Access: nuclei-verified findings ------
    if Path(args.nuclei).exists():
        findings = parse_nuclei_json(Path(args.nuclei).read_text())
        steps.extend(to_plan_steps(findings))

    # -- Privilege escalation: IAM chains -----------------------------
    chains = tagged_chains(iam_graph, ["public-api"], ["secrets-bucket", "admin-role"])
    for c in chains:
        steps.append({
            "phase": "Privilege Escalation", "tactic_id": "TA0004",
            "tactic": "Privilege Escalation",
            "title": f"Escalate {c['entry']} -> {c['target']}",
            "chain": [f"{s['from']} -[{s['relation']}]-> {s['to']}" for s in c["steps"]],
            "z3_reachable": c["z3"]["reachable"],
            "z3_witness": c["z3"]["escalation_witness"],
        })

    # -- Collection: BOLA PoCs over crAPI -----------------------------
    spec = json.loads(SPEC.read_text())
    labels = json.loads(LABELS.read_text())
    pocs = generate_pocs(spec, labels)
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
