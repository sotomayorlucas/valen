"""The autonomous red-team agent: plan -> act -> observe -> re-plan.

Runs an engagement against an authorized target with a bounded budget. A
challenge supplies a goal and a *recipe* (a deterministic plan); the agent
executes it step by step, records an audit trail, and if the success predicate
fails it falls back to the LLM (when available) to propose the next action ---
with the HTTP/formal validators as the arbiter.
"""

from __future__ import annotations

import time
from typing import Dict, List

from .auth import CrApiClient
from .operators import run_operator

State = Dict


class AutonomousAgent:
    def __init__(self, base_url: str, llm=None, max_steps: int = 40,
                 authorize: bool = False):
        self.client = CrApiClient(base_url)
        self.state: State = {"tokens": {}, "forged": {}, "users": [], "vars": {}}
        self.llm = llm
        self.max_steps = max_steps
        self.authorize = authorize
        self.audit: List[Dict] = []
        self.requests = 0

    def step(self, name: str, params: Dict, tier: str = "bounded") -> Dict:
        if tier == "intrusive" and not self.authorize:
            self.audit.append({"op": name, "skipped": "intrusive needs --authorize"})
            return {"skipped": True, "op": name}
        if len(self.audit) >= self.max_steps:
            return {"error": "budget exceeded"}
        obs = run_operator(self.client, self.state, name, params)
        obs.setdefault("op", name)
        self.requests += 1
        self.audit.append({"op": name, "params": {k: v for k, v in params.items()
                                                  if k not in ("password",)},
                           "status": obs.get("status"), "snippet": str(obs.get("body", ""))[:120]})
        return obs

    def solve(self, challenge: Dict) -> Dict:
        start = time.time()
        obs = None
        try:
            obs = challenge["recipe"](self)
        except Exception as exc:  # pragma: no cover - defensive
            obs = {"error": str(exc)}
        solved = bool(challenge["check"](self, obs))
        if not solved and self.llm is not None:
            obs = self._llm_fallback(challenge, obs)
            solved = bool(challenge["check"](self, obs))
        return {
            "challenge": challenge.get("id", challenge.get("name", "?")),
            "solved": solved,
            "requests": self.requests,
            "seconds": round(time.time() - start, 2),
            "audit": self.audit,
            "evidence": str(obs.get("body", ""))[:300] if isinstance(obs, dict) else "",
        }

    def _llm_fallback(self, challenge: Dict, obs: Dict) -> Dict:
        """Ask the LLM to propose the next action when the recipe fell short."""
        try:
            from agent.prompts import SYSTEM
            text = self.llm.complete([
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": (
                    f"Goal: {challenge.get('goal','')}. So far the attempts returned "
                    f"status {obs.get('status')}. Propose ONE next concrete HTTP step "
                    "(method, path, body) as JSON.")},
            ])
            # keep it minimal: log the suggestion, do not auto-execute arbitrary LLM HTTP
            self.audit.append({"op": "llm_suggestion", "snippet": (text or "")[:200]})
        except Exception:
            pass
        return obs
