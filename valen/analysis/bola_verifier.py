"""BOLA/IDOR witness verifier (Z3).

The structural detector flags an *ungated* user-controlled resource access, but
it cannot say whether object-level authorization is enforced. This module closes
that gap with a small SMT model of ownership: the attacker controls an object
selector ``object_id`` and carries a ``session_user_id``; the violation is

    owner(object_id) != session_user_id,

i.e. the requested object belongs to someone else. If the code enforces
ownership (``owner(object_id) == session_user_id`` is a constraint of the
endpoint), the violation is UNSAT --- no BOLA. Otherwise it is SAT, and Z3
returns a concrete witness (the attacker's session and the victim's object).

A key nuance this makes explicit: an *authentication* gate (``login_required``)
only proves the caller is logged in, not that they own the object, so a gated
but not ownership-checked endpoint is still SAT. Only an object-level ownership
predicate (``owner`` / ``current_user`` / ``request.user`` / ``user_id``) blocks
BOLA.

The model is deliberately minimal and its claims are scoped: the witness shows
*satisfiability under the encoded semantics*, not end-to-end exploitability.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import z3

# Heuristic tokens that indicate an object-level ownership predicate.
_OWNERSHIP_TOKENS = (
    "owner", "current_user", "request.user", "session.user", "user_id",
    "belongs_to", "created_by", "tenant",
)


def ownership_predicate_present(code: str) -> bool:
    """True if ``code`` contains a (heuristic) object-level ownership predicate.

    This is a syntactic probe: it is *not* a proof that ownership is correctly
    enforced, only that an ownership constraint appears. The SMT query below is
    the part that turns presence/absence into a sat/unsat verdict.
    """
    lowered = code.lower()
    return any(tok in lowered for tok in _OWNERSHIP_TOKENS)


def _eval(m: z3.ModelRef, e: z3.ExprRef) -> object:
    v = m.eval(e, model_completion=True)
    try:
        return int(v.as_long())
    except Exception:
        return str(v)


def bola_witness(enforce_ownership: bool) -> Tuple[bool, Optional[Dict[str, object]]]:
    """SAT/UNSAT of the BOLA violation ``owner(object_id) != session_user_id``.

    Returns ``(sat, witness)``. ``witness`` is a concrete assignment when
    ``sat`` is True, else ``None``.
    """
    obj = z3.Int("object_id")
    session = z3.Int("session_user_id")
    owner = z3.Function("owner", z3.IntSort(), z3.IntSort())
    violation = owner(obj) != session

    s = z3.Solver()
    if enforce_ownership:
        s.add(owner(obj) == session)  # object-level authorization enforced
    s.add(violation)

    sat = s.check() == z3.sat
    if not sat:
        return False, None
    m = s.model()
    return True, {
        "object_id": _eval(m, obj),
        "session_user_id": _eval(m, session),
        "owner(object_id)": _eval(m, owner(obj)),
    }


def verify_bola(code: str) -> Dict[str, object]:
    """High-level verdict for an endpoint's source.

    Returns a dict with ``enforces_ownership``, ``sat``, ``witness`` and a
    ``verdict`` in {``bola-possible``, ``bola-blocked``}. An authentication-only
    gate does *not* set ``enforces_ownership`` (it is not object authorization),
    so a gated-but-not-owner-scoped endpoint is still ``bola-possible``.
    """
    enforce = ownership_predicate_present(code)
    sat, witness = bola_witness(enforce_ownership=enforce)
    verdict = "bola-blocked" if not sat else "bola-possible"
    return {
        "enforces_ownership": enforce,
        "sat": sat,
        "witness": witness,
        "verdict": verdict,
    }
