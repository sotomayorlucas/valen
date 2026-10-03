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
# A small PCFG-lite prior: structural patterns + common suffixes, ordered by a
# rough probability. Used to order a password-spray so the highest-probability
# candidates are tried first (lockout-aware batching is the caller's job).
_PATTERNS = [
    ("{W}{Year}!", 1.0),   # Summer2024!
    ("{W}123!", 0.9),
    ("{W}123", 0.8),
    ("{W}!", 0.7),
    ("{W}{Year}", 0.6),
    ("{W}", 0.5),
    ("{w}123", 0.45),
    ("{W}1", 0.4),
    ("{w}", 0.35),
    ("{w}!", 0.3),
]

_COMMON_WORDS = [
    "password", "welcome", "summer", "winter", "spring", "autumn", "secret",
    "admin", "letmein", "monkey", "dragon", "qwerty", "iloveyou", "baseball",
    "football", "sunshine", "princess", "shadow", "superman", "batman",
]

_COMMON_YEARS = ["2024", "2025", "2026", "2023", "2022", "2021", "2020", "123"]


def rank_passwords(limit: int = 50) -> List[Dict[str, float]]:
    """Generate and rank candidate passwords by an approximate prior.

    Returns ``[{password, score}]`` sorted by descending likelihood. This is a
    lightweight stand-in for a full PCFG/Markov guesser (OMEN-style); plugging a
    real frequency table or cracked corpus in is the production path.
    """
    scored: Dict[str, float] = {}
    for word in _COMMON_WORDS:
        for year in _COMMON_YEARS:
            for pattern, weight in _PATTERNS:
                p = pattern.replace("{W}", word.capitalize()).replace("{w}", word)
                p = p.replace("{Year}", year)
                scored[p] = max(scored.get(p, 0.0), weight)
    for word in _COMMON_WORDS:
        scored.setdefault(word, 0.2)
    ranked = sorted(scored.items(), key=lambda kv: -kv[1])[:limit]
    return [{"password": p, "score": round(s, 3)} for p, s in ranked]


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
