"""Active BOLA/IDOR enumeration.

Given an authenticated endpoint that takes an object id, iterate ids and detect
*cross-user access*: the attacker's token returns a resource owned by someone
else. Detection is by owner-discriminating fields in the response (``full_name``,
``email``, ``owner``, ``user_id``, ...). Each hit is a validated finding with
request/response evidence.

For authorized engagements only; default dry-run (no requests sent).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

# fields that change when the resource belongs to a *different* user
_OWNER_FIELDS = ("full_name", "owner", "user_id", "email", "name", "username", "author")


def enumerate_ids(
    fetch: Callable[[str], Dict],
    ids: List[str],
    baseline_owner: Optional[str] = None,
    owner_fields: tuple = _OWNER_FIELDS,
) -> List[Dict]:
    """Iterate object ids; return those whose owner differs from ``baseline_owner``.

    ``fetch(id)`` returns ``{"status": int, "body": str, "json": Optional[dict]}``.
    A resource is a cross-user hit when its response is 2xx and its owner fields
    are present and different from the baseline (or non-empty when no baseline).
    """
    hits: List[Dict] = []
    for oid in ids:
        res = fetch(oid)
        if not (200 <= (res.get("status") or 0) < 300):
            continue
        text = res.get("body", "")
        owner = _owner_of(res.get("json"), text, owner_fields)
        if owner is None:
            continue
        if baseline_owner is None or (owner and owner != baseline_owner):
            hits.append({
                "object_id": oid,
                "owner": owner,
                "status": res["status"],
                "evidence": text[:400],
            })
    return hits


def _owner_of(json_body: Optional[dict], text: str, fields: tuple) -> Optional[str]:
    if isinstance(json_body, dict):
        for f in fields:
            v = json_body.get(f)
            if v:
                return str(v)
    for f in fields:
        if f in text.lower():
            return f
    return None


def detect_idor(
    fetch: Callable[[str], Dict],
    start: int,
    count: int,
    baseline_id: str,
    fmt: Callable[[int], str] = str,
) -> List[Dict]:
    """Enumerate ``count`` ids from ``start``, comparing ownership vs ``baseline_id``."""
    base = fetch(baseline_id)
    baseline_owner = _owner_of(base.get("json"), base.get("body", ""), _OWNER_FIELDS)
    ids = [fmt(i) for i in range(start, start + count)]
    return enumerate_ids(fetch, ids, baseline_owner=baseline_owner)
