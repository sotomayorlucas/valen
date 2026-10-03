"""Credential recovery: parse hashcat/john potfiles and record loot.

Hashcat's potfile is ``hash:plaintext`` lines; John's is ``$format$salt$hash:
plaintext``. Both are parsed into ``{hash, plaintext}`` and can be persisted as
``creds`` runs so recovered credentials land on the operation board.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional


def read_hashcat_potfile(path: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or ":" not in line:
            continue
        h, _, pw = line.partition(":")
        out.append({"hash": h.strip(), "plaintext": pw.strip()})
    return out


def read_john_potfile(path: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or ":" not in line:
            continue
        h, _, pw = line.partition(":")
        out.append({"hash": h.strip(), "plaintext": pw.strip()})
    return out


def parse_potfile(path: str, tool: str = "hashcat") -> List[Dict[str, str]]:
    if tool == "john":
        return read_john_potfile(path)
    return read_hashcat_potfile(path)


def record_creds(store, creds: List[Dict[str, str]],
                 engagement_id: Optional[int] = None) -> int:
    if store is None:
        return 0
    n = 0
    for c in creds:
        store.record("creds", c, engagement_id=engagement_id,
                     name=c.get("hash", "")[:40], adapter="potfile",
                     summary=f"recovered {c.get('plaintext', '')}")
        n += 1
    return n
