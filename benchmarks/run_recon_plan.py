"""Reconnaissance -> IR -> attack plan: feed Kali tool output into VALEN.

Parses nmap/masscan output, builds the attack-surface graph, runs the
trust-topology kernels (Fiedler cut + Forman--Ricci) to surface network bridges /
pivot hosts, and turns discovered service versions into CVE hypotheses. Writes
benchmarks/recon_plan.json. By default it ingests the fixture files; pass
``--nmap <file>`` / ``--masscan <file>`` to use your own scan output.

Run the actual tools with a StealthProfile, e.g.:
    nmap -oX - -T2 --max-rate 100 10.0.0.0/24 > scan.xml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.trust import fiedler_boundary, privilege_bridges  # noqa: E402
from valen.redteam.recon import (  # noqa: E402
    hypothesis_for,
    parse_masscan_json,
    parse_nmap_xml,
    recon_to_graph,
)
from valen.redteam.stealth import PRESETS, build_nmap_args  # noqa: E402

NMAP = ROOT / "examples" / "recon" / "nmap.xml"
MASSCAN = ROOT / "examples" / "recon" / "masscan.json"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nmap", type=str, default=str(NMAP))
    ap.add_argument("--masscan", type=str, default=str(MASSCAN))
    ap.add_argument("--profile", type=str, default="sneaky")
    args = ap.parse_args()

    hosts = parse_nmap_xml(Path(args.nmap).read_text())
    hosts += parse_masscan_json(Path(args.masscan).read_text())

    graph = recon_to_graph(hosts)
    bridges = privilege_bridges(graph)
    boundary = [b[0] for b in fiedler_boundary(graph)]

    hypotheses = []
    for h in hosts:
        for s in h.get("services", []):
            v = (s.get("product", "") + " " + s.get("version", "")).strip()
            hint = hypothesis_for(v)
            if hint:
                hypotheses.append({
                    "host": h["ip"], "port": s["port"], "version": v,
                    "hypothesis": hint,
                })

    profile = PRESETS.get(args.profile, PRESETS["sneaky"])
    plan = {
        "profile": profile.name,
        "nmap_command": build_nmap_args(profile, ["<scope>"], "1-1000"),
        "hosts": hosts,
        "trust_bridges": bridges,
        "fiedler_boundary": boundary,
        "cve_hypotheses": hypotheses,
    }

    bridge_desc = ", ".join(f"{b['src_label']}->{b['dst_label']}" for b in bridges[:4])
    print(f"== VALEN recon -> IR (profile={profile.name}) ==")
    print(f"  hosts: {len(hosts)}, services: {sum(len(h['services']) for h in hosts)}")
    print(f"  trust bridges: {bridge_desc}")
    print(f"  CVE hypotheses: {[(x['host'], x['port'], x['hypothesis']) for x in hypotheses]}")
    print(f"  nmap: {' '.join(plan['nmap_command'])}")

    out = ROOT / "benchmarks" / "recon_plan.json"
    out.write_text(json.dumps(plan, indent=2))
    print(f"  plan -> {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
