"""Network map: live hosts + services -> topology graph -> bridges.

Ingests an nmap XML (or any host/service records), builds the network-topology
graph (hosts, services, host<->gateway routing edges), and runs the
trust-topology kernels to surface the network bridges / pivot hosts. Writes
benchmarks/network_map.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from valen.analysis.trust import fiedler_boundary, privilege_bridges  # noqa: E402
from valen.redteam.recon import network_topology_graph, parse_nmap_xml  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nmap", required=True, help="nmap -oX output")
    ap.add_argument("--gateway", required=True, help="gateway/router IP (the routing hub)")
    ap.add_argument("--out", default=str(ROOT / "benchmarks" / "network_map.json"))
    args = ap.parse_args()

    hosts = parse_nmap_xml(Path(args.nmap).read_text())
    graph = network_topology_graph(hosts, args.gateway)

    bridges = privilege_bridges(graph)
    boundary = [b[0] for b in fiedler_boundary(graph)]

    net = {
        "gateway": args.gateway,
        "n_hosts": len(hosts),
        "hosts": [{"ip": h["ip"], "hostname": h["hostname"],
                   "open_ports": [s["port"] for s in h["services"]]} for h in hosts],
        "trust_bridges": bridges,
        "fiedler_boundary": boundary,
    }

    print(f"== VALEN network map ({len(hosts)} hosts, gateway {args.gateway}) ==")
    for h in net["hosts"]:
        print(f"  {h['ip']:<16} {h['hostname'] or '':<24} ports={h['open_ports']}")
    bridge_desc = ", ".join(f"{b['src_label']}<->{b['dst_label']}" for b in bridges[:6])
    print(f"  trust bridges (pivots): {bridge_desc}")
    print(f"  fiedler boundary: {boundary[:6]}")

    Path(args.out).write_text(json.dumps(net, indent=2))
    print(f"  map -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
