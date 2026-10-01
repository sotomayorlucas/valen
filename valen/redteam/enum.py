"""Enumeration ingestion: gobuster / ffuf / amass / theHarvester output -> IR.

Recon finds hosts and services; *enumeration* finds hidden endpoints, parameters
and subdomains. This module parses the output of the Kali enumeration tools and
turns the discoveries into IR nodes, including a *shadow-API* signal: endpoints
that exist on the target but are missing from its published OpenAPI spec.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List

from ..ir import EdgeKind, Graph, NodeKind


def parse_gobuster(text: str) -> List[Dict]:
    """Parse gobuster ``dir`` output lines ``/path (Status: 200) [Size: 1234]``."""
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "=", "[", "Starting", "Finished")):
            continue
        m = re.match(r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", line)
        if m:
            out.append({"path": m.group(1), "status": int(m.group(2)),
                        "size": int(m.group(3)), "tool": "gobuster"})
    return out


def parse_ffuf_json(text: str) -> List[Dict]:
    """Parse ffuf ``-json`` NDJSON records."""
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = d.get("url", "")
        out.append({
            "path": url.split("//", 1)[-1] if "//" in url else url,
            "status": d.get("status"),
            "size": d.get("length"),
            "tool": "ffuf",
            "keywords": d.get("words"),
        })
    return out


def parse_amass_json(text: str) -> List[Dict]:
    """Parse amass ``-json`` NDJSON records into subdomain records."""
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = d.get("name") or d.get("domain") or d.get("hostname")
        if not name:
            continue
        addrs = [a.get("ip") for a in d.get("addresses", []) if a.get("ip")]
        out.append({"path": name, "status": None, "size": None,
                    "tool": "amass", "ip": addrs[0] if addrs else ""})
    return out


def parse_harvester(text: str) -> List[Dict]:
    """Parse theHarvester table output (emails/hosts) into records."""
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if "@" in line:
            for token in re.findall(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", line):
                out.append({"path": token, "status": None, "size": None,
                            "tool": "theHarvester"})
        elif "." in line and not line.startswith(("+", "*", "-", "=", "[", "|")):
            for host in re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", line):
                out.append({"path": host, "status": None, "size": None,
                            "tool": "theHarvester"})
    return out


def enum_to_graph(records: List[Dict]) -> Graph:
    """Discoveries as IR nodes, linked to a synthetic 'target' root."""
    graph = Graph()
    graph.meta = {"language": "enum", "n": len(records)}
    graph.add_node("target", NodeKind.FUNCTION, "target", attrs={"kind": "root"})
    for i, r in enumerate(records):
        nid = f"e{i}"
        label = r.get("path", "")
        graph.add_node(nid, NodeKind.FUNCTION, label,
                       attrs={"kind": r.get("tool", "enum"),
                              "status": r.get("status"),
                              "size": r.get("size")})
        graph.add_edge("target", nid, EdgeKind.CALL, attrs={"relation": "discovered"})
    return graph


def shadow_endpoints(records: List[Dict], spec_paths: List[str]) -> List[str]:
    """Discovered HTTP paths not present in the published OpenAPI spec.

    A discovery is *shadow* when it is neither equal to nor a prefix of any
    published path template (``spec_paths``). A base path such as
    ``/identity/api/v2/user`` is considered covered because the spec expands it
    (``/identity/api/v2/user/dashboard`` etc.).
    """
    shadow: List[str] = []
    for r in records:
        if r.get("status") is None or r.get("tool") not in ("gobuster", "ffuf"):
            continue
        p = r["path"]
        if not p.startswith("/"):
            continue
        if any(sp == p or sp.startswith(p) for sp in spec_paths if sp.startswith("/")):
            continue
        shadow.append(p)
    return sorted(set(shadow))
