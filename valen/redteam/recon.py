"""Kali recon ingestion: parse tool output into the VALEN IR.

nmap ``-oX`` and masscan ``-oJ`` output become an attack-surface graph --- hosts
as nodes, open services as attributed nodes, edges host -> service --- so the
same spectral/geometric kernels (Fiedler cut, Forman--Ricci) surface the network
bridges and pivot hosts, and a version -> CVE hint table turns discovered
services into *hypotheses* for the neuro-symbolic loop.

For authorized engagements only; run with an explicit scope and a StealthProfile.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from ..ir import EdgeKind, Graph, NodeKind

# Illustrative version -> CVE hints (a hypothesis source, NOT a scanner).
VERSION_CVE_HINTS: Dict[str, str] = {
    "vsftpd 2.3.4": "CVE-2011-2523 (backdoor)",
    "Apache httpd 2.4.49": "CVE-2021-41773 (path traversal)",
    "OpenSSH 7.2": "CVE-2016-6210 (user enumeration)",
}


def parse_nmap_xml(xml_text: str) -> List[Dict]:
    """Parse nmap ``-oX`` into ``{ip, hostname, services: [{port, proto, service, product, version}]}``."""
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        ip = ""
        hostname = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
        for hn in host.findall("hostnames/hostname"):
            hostname = hn.get("name", "")
        services = []
        for port in host.findall("ports/port"):
            svc = port.find("service")
            product = (svc.get("product", "") if svc is not None else "")
            version = (svc.get("version", "") if svc is not None else "")
            services.append({
                "port": int(port.get("portid", 0)),
                "proto": port.get("protocol", ""),
                "service": (svc.get("name", "") if svc is not None else ""),
                "product": product,
                "version": version,
            })
        if ip:
            hosts.append({"ip": ip, "hostname": hostname, "services": services})
    return hosts


def parse_masscan_json(json_text: str) -> List[Dict]:
    """Parse masscan ``-oJ`` into ``{ip, services: [{port, proto}]}``."""
    data = json.loads(json_text)
    hosts: Dict[str, Dict] = {}
    for entry in data:
        ip = entry.get("ip", "")
        ports = entry.get("ports", [])
        for p in ports:
            hosts.setdefault(ip, {"ip": ip, "hostname": "", "services": []})
            hosts[ip]["services"].append({
                "port": p.get("port", 0),
                "proto": p.get("proto", ""),
                "service": "", "product": "", "version": "",
            })
    return list(hosts.values())


def recon_to_graph(hosts: List[Dict]) -> Graph:
    """Build the attack-surface IR graph from parsed host/service records."""
    graph = Graph()
    graph.meta = {"language": "recon", "n_hosts": len(hosts)}
    for h in hosts:
        ip = h.get("ip", "")
        label = h.get("hostname") or ip
        graph.add_node(ip, NodeKind.FUNCTION, label, attrs={
            "hostname": h.get("hostname", ""), "kind": "host",
        })
        for s in h.get("services", []):
            sid = f"{ip}:{s['port']}"
            version = (s.get("product", "") + " " + s.get("version", "")).strip()
            graph.add_node(sid, NodeKind.FUNCTION,
                           f"{s['service']} {version}".strip() or str(s["port"]),
                           attrs={
                               "kind": "service", "port": s["port"],
                               "proto": s["proto"], "service": s["service"],
                               "version": version,
                           })
            graph.add_edge(ip, sid, EdgeKind.CALL, attrs={"relation": "open"})
    return graph


def hypothesis_for(version: str) -> Optional[str]:
    """Map a discovered service/version to an illustrative CVE hypothesis."""
    v = version.strip()
    for key, hint in VERSION_CVE_HINTS.items():
        if key.lower() in v.lower():
            return hint
    return None
