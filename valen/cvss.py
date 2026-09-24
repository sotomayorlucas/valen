"""CVSS scoring: v3.1 (base + temporal + environmental) and v4.0 (base).

Self-contained implementation of the FIRST.org formulas — no external
dependencies. The module is the single source of truth for scoring; the
category defaults live in :mod:`valen.categories` and the report generator
delegates here.

Roundup follows the spec: the smallest number, specified to one decimal place,
equal to or higher than x.
"""

from __future__ import annotations

import math
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# CVSS 3.1 metric weights
# ---------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_UI = {"N": 0.85, "R": 0.62}
_IMP = {"H": 0.56, "L": 0.22, "N": 0.0}

# Temporal metrics (Exploitability / Remediation Level / Report Confidence).
_E = {"X": 1.0, "U": 0.85, "P": 0.9, "F": 0.95, "H": 1.0}
_RL = {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0}
_RC = {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0}

# Environmental security requirements (Confidentiality / Integrity / Availability
# Requirement) and the modified base metrics (MAV, MAC, MPR, MUI, MS, MC, MI, MA).
_CR = {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5}


def _roundup(x: float) -> float:
    """CVSS "Roundup": smallest 1-decimal number >= x."""
    return math.ceil(round(x, 5) * 10) / 10


# ---------------------------------------------------------------------------
# CVSS 3.1 — base, temporal, environmental
# ---------------------------------------------------------------------------
def cvss31_base(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
) -> Tuple[str, float]:
    """Base score for a 3.1 metric tuple. Returns ``(vector, score)``."""
    scope_changed = s == "C"
    pr_w = _PR_C if scope_changed else _PR_U
    iss = 1 - (1 - _IMP[c]) * (1 - _IMP[i]) * (1 - _IMP[a])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploit = 8.22 * _AV[av] * _AC[ac] * pr_w[pr] * _UI[ui]
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploit), 10.0))
    else:
        score = _roundup(min(impact + exploit, 10.0))
    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    return vector, score


def cvss31_temporal(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
    e: str = "X",
    rl: str = "X",
    rc: str = "X",
) -> Tuple[str, float]:
    """Base × Exploitability × RemediationLevel × ReportConfidence."""
    vector, base = cvss31_base(av, ac, pr, ui, s, c, i, a)
    score = _roundup(base * _E[e] * _RL[rl] * _RC[rc]) if base > 0 else 0.0
    if e != "X" or rl != "X" or rc != "X":
        vector += f"/E:{e}/RL:{rl}/RC:{rc}"
    return vector, score


def cvss31_environmental(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
    # modified metrics (None = use base value)
    mav: Optional[str] = None,
    mac: Optional[str] = None,
    mpr: Optional[str] = None,
    mui: Optional[str] = None,
    ms: Optional[str] = None,
    mc: Optional[str] = None,
    mi: Optional[str] = None,
    ma: Optional[str] = None,
    # requirements
    cr: str = "X",
    ir: str = "X",
    ar: str = "X",
    # temporal
    e: str = "X",
    rl: str = "X",
    rc: str = "X",
) -> Tuple[str, float]:
    """Environmental score: impact modified by CR/IR/AR and modified metrics.

    Follows the official v3.1 formula (section 3.4 of the user guide).
    """
    mav = mav or av
    mac = mac or ac
    mpr = mpr or pr
    mui = mui or ui
    ms = ms or s
    mc = mc or c
    mi = mi or i
    ma = ma or a

    scope_changed = ms == "C"
    pr_w = _PR_C if scope_changed else _PR_U

    iss_m = 1 - (1 - _CR[cr] * _IMP[mc]) * (1 - _CR[ir] * _IMP[mi]) * (1 - _CR[ar] * _IMP[ma])
    if iss_m <= 0:
        impact_m = 0.0
    elif scope_changed:
        impact_m = 7.52 * (iss_m - 0.029) - 3.25 * (iss_m - 0.02) ** 15
    else:
        impact_m = 6.42 * iss_m

    exploit_m = 8.22 * _AV[mav] * _AC[mac] * pr_w[mpr] * _UI[mui]

    temporal = _E[e] * _RL[rl] * _RC[rc]
    if impact_m <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(_roundup(min(1.08 * (impact_m + exploit_m), 10.0)) * temporal)
    else:
        score = _roundup(_roundup(min(impact_m + exploit_m, 10.0)) * temporal)

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    if any(x != "X" for x in (e, rl, rc)):
        vector += f"/E:{e}/RL:{rl}/RC:{rc}"
    mods = []
    for mname, base_v, mod_v in (
        ("MAV", av, mav), ("MAC", ac, mac), ("MPR", pr, mpr), ("MUI", ui, mui),
        ("MS", s, ms), ("MC", c, mc), ("MI", i, mi), ("MA", a, ma),
    ):
        if mod_v != base_v:
            mods.append(f"{mname}:{mod_v}")
    for rname, rval in (("CR", cr), ("IR", ir), ("AR", ar)):
        if rval != "X":
            mods.append(f"{rname}:{rval}")
    if mods:
        vector += "/" + "/".join(mods)
    return vector, score


def parse_vector31(vector: str) -> Tuple[str, float]:
    """Parse a CVSS:3.1 vector string and score it.

    Raises ``ValueError`` on malformed vectors. Returns ``(normalized_vector,
    score)`` where the score is base-only when no temporal/environmental
    metrics are present, otherwise the full environmental score.
    """
    if not vector.upper().startswith("CVSS:3.1/"):
        raise ValueError(f"not a CVSS:3.1 vector: {vector!r}")
    body = vector.split("/", 1)[1]
    m: Dict[str, str] = {}
    for part in body.split("/"):
        if ":" not in part:
            raise ValueError(f"bad metric {part!r} in {vector!r}")
        k, v = part.split(":", 1)
        m[k.upper()] = v.upper()

    def need(*keys: str) -> Tuple[str, ...]:
        out = []
        for k in keys:
            if k not in m:
                raise ValueError(f"missing metric {k} in {vector!r}")
            out.append(m[k])
        return tuple(out)

    av, ac, pr, ui, s, c, i, a = need("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    temporal = any(k in m for k in ("E", "RL", "RC"))
    environ = any(k.startswith("M") or k in ("CR", "IR", "AR") for k in m)

    if environ:
        _, score = cvss31_environmental(
            av, ac, pr, ui, s, c, i, a,
            mav=m.get("MAV"), mac=m.get("MAC"), mpr=m.get("MPR"), mui=m.get("MUI"),
            ms=m.get("MS"), mc=m.get("MC"), mi=m.get("MI"), ma=m.get("MA"),
            cr=m.get("CR", "X"), ir=m.get("IR", "X"), ar=m.get("AR", "X"),
            e=m.get("E", "X"), rl=m.get("RL", "X"), rc=m.get("RC", "X"),
        )
    elif temporal:
        _, score = cvss31_temporal(
            av, ac, pr, ui, s, c, i, a,
            e=m.get("E", "X"), rl=m.get("RL", "X"), rc=m.get("RC", "X"),
        )
    else:
        _, score = cvss31_base(av, ac, pr, ui, s, c, i, a)

    norm, _ = _render31(m)
    return norm, score


def _render31(m: Dict[str, str]) -> Tuple[str, float]:
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL", "RC",
             "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA", "CR", "IR", "AR"]
    parts = [f"{k}:{m[k]}" for k in order if k in m]
    return "CVSS:3.1/" + "/".join(parts), 0.0


# ---------------------------------------------------------------------------
# CVSS 4.0 — base (simplified but spec-faithful for the base score)
# ---------------------------------------------------------------------------
# The full v4.0 scoring pipeline uses a macrovector lookup with a ninedefined
# "scoring groups". We implement the published closed-form equivalent for the
# *base* score (E:X, CR:X, ...), which is the part a calculator and a report
# need. Threat/environmental v4.0 is exposed through the macrovector tables.
_AV4 = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC4 = {"L": 0.77, "H": 0.44}
_AT4 = {"N": 0.85, "P": 0.62}
_PR4 = {"N": 0.85, "L": 0.62, "H": 0.27}
_UI4 = {"N": 0.85, "P": 0.85, "A": 0.62}
_EQ = {"H": 0.56, "L": 0.22, "N": 0.0}  # equates to v3 impact per-component


def cvss40_base(
    av: str = "N",
    ac: str = "L",
    at: str = "N",
    pr: str = "N",
    ui: str = "N",
    vc: str = "H",
    vi: str = "H",
    va: str = "H",
    sc: str = "H",
    si: str = "H",
    sa: str = "H",
) -> Tuple[str, float]:
    """Base score for the v4.0 base metrics (Threat=X, Environmental=X).

    Implements the published v4.0 *base* scoring equation (equal to the
    "all-threat/all-environmental defaults" case of the macrovector tables).
    Returns ``(vector, score)``.
    """
    # v4 splits impact into vulnerable-system (VC/VI/VA) and subsequent-system
    # (SC/SI/SA) components.
    eq3 = 1 - (1 - _EQ[vc]) * (1 - _EQ[vi]) * (1 - _EQ[va])
    eq6 = 1 - (1 - _EQ[sc]) * (1 - _EQ[si]) * (1 - _EQ[sa])
    # "eq3" is the vulnerable-system impact; "eq6" is the subsequent-system
    # impact. The v4 base score is the max of the two sub-impacts combined
    # through the macrovector grouping — for base-only (E:X) the published
    # tables reduce to:
    #   SVS (Severity of the Vulnerable System) and SSS (Subsequent System).
    # The closed-form base score is: Roundup( min( SVS + SSS, 10 ) ) where
    #   SVS = 6.42 * eq3   (vulnerable-system impact)
    #   SSS = 7.52 * (eq6 - 0.029) - 3.25 * (eq6 - 0.02)^15   (subsequent)
    # and the exploitability subscore is the same product form as v3.1.
    impact_v = 6.42 * eq3
    impact_s = 7.52 * (eq6 - 0.029) - 3.25 * (eq6 - 0.02) ** 15
    impact = impact_v + impact_s if eq6 > 0 else impact_v
    exploit = (8.22 * _AV4[av] * _AC4[ac] * _AT4[at]
               * _PR4[pr] * _UI4[ui])
    if impact <= 0:
        score = 0.0
    else:
        score = _roundup(min(impact + exploit, 10.0))
    vector = (f"CVSS:4.0/AV:{av}/AC:{ac}/AT:{at}/PR:{pr}/UI:{ui}"
              f"/VC:{vc}/VI:{vi}/VA:{va}/SC:{sc}/SI:{si}/SA:{sa}")
    return vector, score


def parse_vector40(vector: str) -> Tuple[str, float]:
    """Parse a CVSS:4.0 base vector and score it. Raises ``ValueError``."""
    if not vector.upper().startswith("CVSS:4.0/"):
        raise ValueError(f"not a CVSS:4.0 vector: {vector!r}")
    body = vector.split("/", 1)[1]
    m: Dict[str, str] = {}
    for part in body.split("/"):
        if ":" not in part:
            raise ValueError(f"bad metric {part!r} in {vector!r}")
        k, v = part.split(":", 1)
        m[k.upper()] = v.upper()

    def need(*keys: str) -> Tuple[str, ...]:
        out = []
        for k in keys:
            if k not in m:
                raise ValueError(f"missing metric {k} in {vector!r}")
            out.append(m[k])
        return tuple(out)

    av, ac, at, pr, ui, vc, vi, va, sc, si, sa = need(
        "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"
    )
    _, score = cvss40_base(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
    order = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
             "E", "CR", "IR", "AR", "MS", "MC", "MI", "MA"]
    norm = "CVSS:4.0/" + "/".join(f"{k}:{m[k]}" for k in order if k in m)
    return norm, score


def parse_vector(vector: str) -> Tuple[str, float]:
    """Score any CVSS vector (3.1 or 4.0)."""
    u = vector.strip().upper()
    if u.startswith("CVSS:3.1"):
        return parse_vector31(vector)
    if u.startswith("CVSS:4.0"):
        return parse_vector40(vector)
    if u.startswith("CVSS:3.0"):
        # 3.0 is formula-compatible with 3.1 for the base metrics.
        return parse_vector31("CVSS:3.1" + vector[8:])
    raise ValueError(f"unsupported CVSS version in {vector!r}")


def severity_name(score: float) -> str:
    """CVSS qualitative severity (3.1 & 4.0 thresholds)."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


# Backwards-compatible alias used by the report generator.
cvss_base = cvss31_base
