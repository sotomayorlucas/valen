"""Credential recovery: parse hashcat/john potfiles and record loot.

Hashcat's potfile is ``hash:plaintext`` lines; John's is ``$format$salt$hash:
plaintext``. Both are parsed into ``{hash, plaintext}`` and can be persisted as
``creds`` runs so recovered credentials land on the operation board.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

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


# -- probabilistic password ranking (spray ordering) ------------------------
# A full PCFG (Weir-style) prior, learned from a cracked corpus (potfile) when
# available, else a small built-in seed list. Ordered in decreasing probability.
def rank_passwords(limit: int = 50, corpus: Optional[List[str]] = None) -> List[Dict[str, float]]:
    """Rank candidate passwords by an approximate PCFG prior.

    ``corpus`` is a list of known/plaintext passwords to train on; when omitted a
    built-in seed list is used. Returns ``[{password, score}]`` ordered by
    descending likelihood (``score`` is the model probability).
    """
    from .pcfg import _SEED_CORPUS, PCFG

    pcfg = PCFG().train(corpus or _SEED_CORPUS)
    guesses = pcfg.generate(limit)
    return [{"password": g["password"], "score": g["prob"]} for g in guesses]


def train_pcfg_from_potfile(path: str) -> "PCFG":  # noqa: F821
    from .pcfg import PCFG

    return PCFG.from_potfile(path)


def spray_batches(domain: str, dc: str, users_file: str,
                  candidates: Optional[List[str]] = None,
                  per_batch: int = 2) -> List[Dict[str, Any]]:
    """Split a spray into lockout-aware batches (per account, per window).

    Returns a list of ``{batch, command}`` using the ranked candidates.
    """
    from .ad.attacks import spray_command

    if candidates is None:
        candidates = [c["password"] for c in rank_passwords()]
    batches = []
    for i in range(0, len(candidates), per_batch):
        chunk = candidates[i:i + per_batch]
        for pw in chunk:
            batches.append({
                "batch": i // per_batch,
                "command": spray_command(domain, dc, users_file, pw),
            })
    return batches
