"""Operation board: map an engagement's runs onto the kill chain.

Turns the persisted run history into a per-tactic board (PTES/ATT&CK order) with
technique tags, so the SPA can show progress across the kill chain for a given
engagement. Live activity (SSE) augments the board as new runs land.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .redteam.mitre import PHASE_ORDER, technique_name

# run/adapter kind -> (tactic_id, technique, phase label)
RUN_PHASE = {
    "analyze": ("TA0007", "T1592", "Discovery"),
    "compare": ("TA0007", "T1592", "Discovery"),
    "dynamic": ("TA0002", "T1059", "Execution"),
    "pentest": ("TA0009", "T1213", "Collection"),
    "ad": ("TA0006", "T1558", "Credential Access"),
    "c2": ("TA0011", "T1071", "Command and Control"),
}

_TACTIC_NAMES = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration", "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _classify(kind: str) -> Dict[str, str]:
    tid, tech, phase = RUN_PHASE.get(kind, ("TA0007", "T1592", "Discovery"))
    return {"tactic_id": tid, "tactic": _TACTIC_NAMES.get(tid, tid),
            "technique": tech, "technique_name": technique_name(tech), "phase": phase}


def build_board(runs: List[Dict[str, Any]], engagement_id: Optional[int] = None) -> Dict[str, Any]:
    """Group runs by kill-chain tactic (ATT&CK order)."""
    phases: Dict[str, Dict[str, Any]] = {}
    for r in runs:
        if engagement_id is not None and r.get("engagement_id") != engagement_id:
            continue
        info = _classify(r.get("kind", ""))
        tid = info["tactic_id"]
        phases.setdefault(tid, {
            "tactic_id": tid, "tactic": info["tactic"],
            "order": PHASE_ORDER.get(tid, 99), "items": [],
        })
        phases[tid]["items"].append({
            "kind": r.get("kind", ""), "name": r.get("name", ""),
            "adapter": r.get("adapter", ""), "summary": r.get("summary", ""),
            "technique": info["technique"], "technique_name": info["technique_name"],
            "ts": r.get("created_at"),
        })
    ordered = sorted(phases.values(), key=lambda p: p["order"])
    total = sum(len(p["items"]) for p in ordered)
    return {
        "engagement_id": engagement_id,
        "phases": ordered,
        "total_runs": total,
        "techniques": sorted({i["technique"] for p in ordered for i in p["items"]}),
    }


def board_from_store(store, engagement_id: Optional[int] = None,
                     limit: int = 500) -> Dict[str, Any]:
    if store is None:
        return {"engagement_id": engagement_id, "phases": [], "total_runs": 0, "techniques": []}
    runs = store.recent_runs(limit=limit)
    return build_board(runs, engagement_id=engagement_id)
