"""Hybrid web-pentest agent (human-in-the-loop).

Generalizes the crAPI-specific executor into a *planner*: given the engagement
context (discovered services / endpoints / findings), it proposes the next
kill-chain actions. Every action is queued for operator approval; intrusive
actions additionally require the engagement ``--authorize`` flag. VALEN never
runs an intrusive action on its own — the operator decides.

An optional LLM refines the proposal list; without one, a deterministic ruleset
covers the recon -> enum -> exploit -> post phases.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# (phase, tactic_id, technique, tier, title, command builder)
# ``command`` returns a list[str] or a dict describing how to run the step.
ActionBuilder = Callable[[Dict[str, Any]], Any]


@dataclass
class Action:
    id: str
    phase: str
    tactic_id: str
    technique: str
    tier: str  # bounded | intrusive
    title: str
    command: Any
    rationale: str = ""
    status: str = "pending"  # pending | approved | denied
    created_at: float = field(default_factory=time.time)
    engagement_id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        return d


def _nmap(ctx: Dict[str, Any]) -> Any:
    host = ctx.get("target", "<scope>")
    return ["nmap", "-sV", "-Pn", "-T2", "--top-ports", "1000", host]


def _gobuster(ctx: Dict[str, Any]) -> Any:
    host = ctx.get("target", "http://<scope>")
    return ["gobuster", "dir", "-u", host, "-w", "/usr/share/wordlists/dirb/common.txt"]


def _nuclei(ctx: Dict[str, Any]) -> Any:
    host = ctx.get("target", "<scope>")
    return ["nuclei", "-u", host, "-severity", "critical,high,medium", "-jsonl"]


def _sqlmap(ctx: Dict[str, Any]) -> Any:
    url = ctx.get("target", "<scope>")
    return ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1"]


def _poc(ctx: Dict[str, Any]) -> Any:
    return {"generator": "valen.redteam.poc.render_poc", "path": ctx.get("path", ""),
            "method": ctx.get("method", "GET"), "id_params": ctx.get("id_params", [])}


def _c2(ctx: Dict[str, Any]) -> Any:
    from ..redteam.c2 import c2_plan  # type: ignore

    return c2_plan(ctx.get("lhost", "<lhost>"), int(ctx.get("lport", 443)))["implant"]


RULES: List[Dict[str, Any]] = [
    {"phase": "recon", "tactic_id": "TA0007", "technique": "T1046", "tier": "bounded",
     "title": "Port/service discovery", "needs": "no_services", "build": _nmap,
     "rationale": "map the attack surface before anything else"},
    {"phase": "enum", "tactic_id": "TA0007", "technique": "T1083", "tier": "bounded",
     "title": "Content discovery (gobuster)", "needs": "has_services", "build": _gobuster,
     "rationale": "enumerate paths/endpoints missing from the spec"},
    {"phase": "enum", "tactic_id": "TA0007", "technique": "T1595.002", "tier": "bounded",
     "title": "Template scan (nuclei)", "needs": "has_services", "build": _nuclei,
     "rationale": "fingerprint + low-risk known-vuln checks"},
    {"phase": "exploit", "tactic_id": "TA0002", "technique": "T1190", "tier": "bounded",
     "title": "SQL injection probe (sqlmap)", "needs": "has_sqli_candidate", "build": _sqlmap,
     "rationale": "validate a taint-ranked SQL injection candidate"},
    {"phase": "exploit", "tactic_id": "TA0009", "technique": "T1213", "tier": "bounded",
     "title": "Generate BOLA/IDOR PoC", "needs": "has_idor_candidate", "build": _poc,
     "rationale": "turn a structural finding into a runnable repro"},
    {"phase": "exploit", "tactic_id": "TA0011", "technique": "T1071", "tier": "intrusive",
     "title": "Deploy implant (Sliver)", "needs": "has_services", "build": _c2,
     "rationale": "establish C2 on a compromised host (authorized only)"},
]


def _needs_ok(need: str, ctx: Dict[str, Any]) -> bool:
    services = ctx.get("services") or []
    findings = ctx.get("findings") or []
    if need == "no_services":
        return not services
    if need == "has_services":
        return bool(services)
    if need == "has_sqli_candidate":
        return any((f.get("category") in ("sql", "sqli")) for f in findings)
    if need == "has_idor_candidate":
        return any((f.get("category") in ("idor", "bola")) for f in findings)
    return False


def plan_actions(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Deterministic proposals for the current context (one per matching rule)."""
    out = []
    for rule in RULES:
        if _needs_ok(rule["needs"], ctx):
            out.append({
                "phase": rule["phase"], "tactic_id": rule["tactic_id"],
                "technique": rule["technique"], "tier": rule["tier"],
                "title": rule["title"], "rationale": rule["rationale"],
                "command": rule["build"](ctx),
            })
    return out


class ApprovalQueue:
    """In-memory queue of proposed actions awaiting operator approval."""

    def __init__(self) -> None:
        self._actions: Dict[str, Action] = {}

    def propose(self, ctx: Dict[str, Any], engagement_id: Optional[int] = None) -> List[Action]:
        created = []
        for a in plan_actions(ctx):
            act = Action(id=uuid.uuid4().hex[:12], engagement_id=engagement_id, **a)
            self._actions[act.id] = act
            created.append(act)
        return created

    def add(self, action: Action) -> Action:
        self._actions[action.id] = action
        return action

    def list(self, engagement_id: Optional[int] = None,
             status: Optional[str] = None) -> List[Action]:
        out = list(self._actions.values())
        if engagement_id is not None:
            out = [a for a in out if a.engagement_id == engagement_id]
        if status:
            out = [a for a in out if a.status == status]
        return sorted(out, key=lambda a: a.created_at)

    def get(self, action_id: str) -> Optional[Action]:
        return self._actions.get(action_id)

    def decide(self, action_id: str, approve: bool, authorize: bool = False) -> Dict[str, Any]:
        act = self._actions.get(action_id)
        if act is None:
            return {"error": "unknown action"}
        if act.status != "pending":
            return {"error": f"action already {act.status}"}
        if approve and act.tier == "intrusive" and not authorize:
            return {"error": "intrusive action requires --authorize"}
        act.status = "approved" if approve else "denied"
        return {"id": act.id, "status": act.status, "tier": act.tier,
                "command": act.command if approve else None}


def propose_with_llm(ctx: Dict[str, Any], llm: Any) -> List[Dict[str, Any]]:
    """Ask an LLM to refine the proposal list (falls back to the ruleset)."""
    base = plan_actions(ctx)
    if llm is None:
        return base
    try:
        text = llm.complete([
            {"role": "system", "content":
             "You are a red-team planner. Given the engagement context, reply with "
             "ONLY a JSON array of proposed next actions, each {phase,tactic_id,"
             "technique,tier,title,rationale,command}."},
            {"role": "user", "content": str(ctx)},
        ])
        import json
        extra = json.loads(text)
        if isinstance(extra, list):
            return base + [e for e in extra if isinstance(e, dict)]
    except Exception:  # noqa: BLE001
        pass
    return base
