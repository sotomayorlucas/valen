"""The crAPI challenge registry: goal, recipe, and success predicate per challenge.

The 18 challenges are transcribed from crAPI's official documentation
(``docs/challenges.md``). Each entry has:

* ``goal`` -- what the agent must achieve;
* ``recipe(agent)`` -- a deterministic plan of operator steps, returning the
  final observation;
* ``check(agent, obs)`` -- the success predicate (verified against responses).

Some recipes are best-effort attempts (the harness reports the honest solve
rate); the LLM fallback in the executor can propose the missing step.
"""

from __future__ import annotations

import uuid
from typing import Dict

PASSWORD = "Passw0rd!123"


def _fresh(agent, prefix: str) -> Dict:
    suf = uuid.uuid4().hex[:8]
    email = f"{prefix}-{suf}@example.com"
    number = f"9{int(uuid.uuid4().hex, 16) % 10**9:09d}"
    agent.step("signup", {"name": prefix.capitalize(), "email": email,
                          "number": number, "password": PASSWORD}, tier="intrusive")
    agent.step("login", {"email": email, "password": PASSWORD})
    return {"email": email, "number": number, "token": agent.state["tokens"].get(email, "")}


# --- recipes ---------------------------------------------------------------

def _jwt_takeover(agent):
    victim = _fresh(agent, "victim")
    _fresh(agent, "attacker")
    agent.step("forge_jwt", {"sub": victim["email"], "technique": "kid_path_traversal"})
    forged = agent.state["forged"][victim["email"]]
    return agent.step("http", {"method": "GET", "path": "/identity/api/v2/user/dashboard",
                               "token": forged})


def _idor_orders(agent):
    attacker = _fresh(agent, "attacker")
    hits = []
    for i in range(1, 6):
        obs = agent.step("http", {"method": "GET", "path": f"/workshop/api/shop/orders/{i}",
                                  "token": attacker["token"]})
        if obs.get("status") == 200 and attacker["email"] not in str(obs.get("body", "")):
            hits.append(obs)
    return hits[-1] if hits else {"status": 0, "body": ""}


def _unauth_endpoint(agent):
    return agent.step("http", {"method": "GET",
                               "path": "/workshop/api/mechanic/receive_report",
                               "token": ""})


def _unimplemented(agent):
    return {"status": 0, "body": "", "note": "not implemented"}


CHALLENGES: Dict[str, Dict] = {
    "ch1_bola_vehicle": {
        "goal": "read another user's vehicle location", "category": "BOLA",
        "recipe": _unimplemented,
        "check": lambda a, o: "full_name" in str(o.get("body", "")) or "latitude" in str(o.get("body", "")),
    },
    "ch2_bola_report": {
        "goal": "read another user's mechanic report", "category": "BOLA",
        "recipe": _unimplemented,
        "check": lambda a, o: o.get("status") == 200 and "report" in str(o.get("body", "")).lower(),
    },
    "ch3_password_reset": {
        "goal": "reset another user's password", "category": "BrokenAuth",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch4_excessive_exposure": {
        "goal": "leak sensitive info of other users", "category": "Exposure",
        "recipe": _idor_orders,
        "check": lambda a, o: o.get("status") == 200 and "@" in str(o.get("body", "")),
    },
    "ch5_video_internal_prop": {
        "goal": "leak an internal property of a video", "category": "Exposure",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch6_rate_limit": {
        "goal": "detect absence of rate limiting", "category": "RateLimit",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch7_bfla_delete_video": {
        "goal": "delete another user's video", "category": "BFLA",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch8_mass_assignment_free": {
        "goal": "get an item for free (negative quantity)", "category": "MassAssignment",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch9_mass_assignment_balance": {
        "goal": "increase balance by $1000", "category": "MassAssignment",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch10_update_video_props": {
        "goal": "update internal video properties", "category": "MassAssignment",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch11_ssrf": {
        "goal": "make the target fetch an external URL", "category": "SSRF",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch12_nosqli_coupon": {
        "goal": "get free coupons (NoSQLi)", "category": "NoSQLi",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch13_sqli_coupon": {
        "goal": "redeem an already-claimed coupon (SQLi)", "category": "SQLi",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch14_unauthenticated": {
        "goal": "find an endpoint with no auth check", "category": "Unauth",
        "recipe": _unauth_endpoint,
        # no 401/403 means the endpoint processed the request without auth
        "check": lambda a, o: o.get("status") not in (401, 403, 0, None),
    },
    "ch15_jwt_forge": {
        "goal": "forge a valid JWT for another user", "category": "JWT",
        "recipe": _jwt_takeover,
        "check": lambda a, o: o.get("status") == 200 and "email" in str(o.get("body", "")),
    },
    "ch16_llm_prompt_injection": {
        "goal": "prompt-inject the chatbot", "category": "LLM",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch17_llm_extract_creds": {
        "goal": "extract another user's credentials via chatbot", "category": "LLM",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch18_llm_act_as_user": {
        "goal": "make the chatbot act for another user", "category": "LLM",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
}
