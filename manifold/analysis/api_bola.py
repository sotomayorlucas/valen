"""Object-level authorization (BOLA / IDOR / BFLA) detector at the API level.

Operates on an OpenAPI 3 spec. The structural signal for BOLA is *not* the
absence of authentication (all BOLA endpoints are authenticated --- a
``security`` scheme is present), but the presence of a *user-supplied resource
identifier* on a *sensitive* resource: an operation whose path carries an
object placeholder (``{video_id}``) or whose parameters name a resource id
(``report_id``, ``order_id``), accessing a sensitive domain (``vehicle`` /
``order`` / ``video`` / ``report`` / ...), with no indication that the id is
bound to the authenticated principal (``me``/``self``/``current``).

This is a *structural heuristic*, not a proof of exploitability: some flagged
endpoints reference a public resource (or a different flaw class), which is
exactly the precision limit the evaluation exposes.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

_SENSITIVE_HINTS = (
    "vehicle", "video", "order", "report", "document", "invoice", "account",
    "profile", "payment", "message", "ticket", "balance", "location", "coupon",
)

# An id is *not* object-level when it is bound to the authenticated principal.
_SELF_BOUND = ("self", "current", "session", "whoami")


def _is_id_name(name: str) -> bool:
    return name.lower().endswith("id")


def _has_path_id(url: str) -> bool:
    return bool(re.search(r"\{[^}]+\}", url))


def _sensitive(url: str) -> bool:
    lowered = url.lower()
    return any(h in lowered for h in _SENSITIVE_HINTS)


def _self_bound(url: str, params: List[Dict]) -> bool:
    lowered = url.lower()
    if any(t in lowered for t in _SELF_BOUND):
        return True
    for p in params:
        if any(t in p.get("name", "").lower() for t in _SELF_BOUND):
            return True
    return False


def api_bola_candidates(spec: Any) -> List[Tuple[str, str, List[str]]]:
    """Return flagged operations as ``(method, path, object_id_params)``.

    A candidate is an operation with a user-supplied object identifier on a
    sensitive resource that is not bound to the authenticated principal.
    """
    if isinstance(spec, str):
        spec = json.loads(spec)
    out: List[Tuple[str, str, List[str]]] = []
    for url, methods in (spec.get("paths") or {}).items():
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            params = op.get("parameters") or []
            id_params = [
                p.get("name") for p in params
                if _is_id_name(p.get("name", "")) or p.get("in") == "path"
            ]
            has_id = _has_path_id(url) or bool(id_params)
            if not has_id or not _sensitive(url):
                continue
            if _self_bound(url, params):
                continue
            out.append((method.upper(), url, id_params))
    return out
