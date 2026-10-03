"""Live Active Directory collection (bloodhound-python / LDAP).

``bloodhound-python`` writes a directory of ``*_users.json`` / ``*_groups.json`` /
``*_computers.json`` / ``*_domains.json`` / ``*_gpos.json`` / ``*_ous.json``
files. This module builds the collector command and merges those files back into
an :class:`ADGraph`. Collection requires domain credentials and engagement
authorization; it degrades to a command plan when the tool is absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from ...ir import Graph
from .collect import ADGraph, build_graph

COLLECTOR = "bloodhound-python"


def bloodhound_command(domain: str, dc: str, user: str, password: str,
                       collection: str = "All", out_dir: str = "ad-data") -> List[str]:
    return [COLLECTOR, "-c", collection, "-u", f"{user}@{domain}",
            "-p", password, "-ns", dc, "-d", domain, "--zip", "false",
            "-dns-tcp"]


def collect(domain: str, dc: str, user: str, password: str, *,
            execute: bool = False, collection: str = "All",
            out_dir: str = "ad-data", timeout: int = 1800) -> Dict[str, Any]:
    from ..exec import available, run

    cmd = bloodhound_command(domain, dc, user, password, collection, out_dir)
    if not execute:
        return {"command": cmd, "note": "dry-run (pass execute=true and --allow-exec)"}
    if not available(COLLECTOR):
        return {"error": f"{COLLECTOR} not installed", "installed": False, "command": cmd}
    res = run(cmd, timeout=timeout)
    if "error" in res:
        return res
    ad = parse_collection_dir(out_dir)
    res["graph"] = ad_to_graph(ad)
    return res


def parse_collection_dir(directory: str) -> ADGraph:
    """Merge the ``*_*.json`` files written by bloodhound-python into one graph."""
    root = Path(directory)
    merged: Dict[str, List[Any]] = {"users": [], "groups": [], "computers": [],
                                    "domains": [], "gpos": [], "ous": []}
    if not root.is_dir():
        return build_graph(merged)
    for path in sorted(root.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for key in merged:
            if key in data:
                items = data[key]
                merged[key].extend(items if isinstance(items, list) else [items])
    return build_graph(merged)


def ad_to_graph(ad: ADGraph) -> Graph:
    return ad.graph
