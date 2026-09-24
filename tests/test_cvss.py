"""Tests for the CVSS scoring module (v3.1 + v4.0)."""

import pytest

from valen.cvss import (
    cvss31_base,
    cvss31_environmental,
    cvss31_temporal,
    cvss40_base,
    parse_vector,
    parse_vector31,
    parse_vector40,
    severity_name,
)


# ---------------------------------------------------------------------------
# CVSS 3.1 base
# ---------------------------------------------------------------------------
def test_cvss31_canonical_98():
    vector, score = cvss31_base("N", "L", "N", "N", "U", "H", "H", "H")
    assert score == 9.8
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss31_canonical_10_scope_changed():
    _, score = cvss31_base("N", "L", "N", "N", "C", "H", "H", "H")
    assert score == 10.0


def test_cvss31_no_impact_is_zero():
    _, score = cvss31_base("N", "L", "N", "N", "U", "N", "N", "N")
    assert score == 0.0


def test_cvss31_low_vector():
    # AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N = 1.8
    # (ISS=0.22, Impact=1.4124, Expl=0.3330, Roundup(1.7454)=1.8)
    _, score = cvss31_base("L", "H", "H", "R", "U", "L", "N", "N")
    assert score == 1.8


def test_cvss31_medium_vector():
    # AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L = 5.0
    # (ISS=0.525448, Impact=3.3734, Expl=1.6201, Roundup(4.9935)=5.0)
    _, score = cvss31_base("N", "H", "N", "R", "U", "L", "L", "L")
    assert score == 5.0


def test_cvss31_physical_vector():
    # AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 6.8
    # (ISS=0.914816, Impact=5.8731, Expl=0.9146, Roundup(6.7877)=6.8)
    _, score = cvss31_base("P", "L", "N", "N", "U", "H", "H", "H")
    assert score == 6.8


def test_cvss31_ordering():
    _, low = cvss31_base("P", "H", "H", "R", "U", "L", "N", "N")
    _, high = cvss31_base("N", "L", "N", "N", "U", "H", "H", "H")
    assert low < high


# ---------------------------------------------------------------------------
# CVSS 3.1 temporal / environmental
# ---------------------------------------------------------------------------
def test_cvss31_temporal_discounts_score():
    _, base = cvss31_base("N", "L", "N", "N", "U", "H", "H", "H")
    _, temporal = cvss31_temporal("N", "L", "N", "N", "U", "H", "H", "H",
                                  e="U", rl="T", rc="R")
    assert 0 < temporal < base


def test_cvss31_temporal_vector_appends_metrics():
    vec, _ = cvss31_temporal("N", "L", "N", "N", "U", "H", "H", "H",
                             e="H", rl="O", rc="C")
    assert "/E:H/RL:O/RC:C" in vec


def test_cvss31_temporal_full_confidence_keeps_base():
    _, base = cvss31_base("N", "L", "N", "N", "U", "H", "H", "H")
    _, temporal = cvss31_temporal("N", "L", "N", "N", "U", "H", "H", "H",
                                  e="H", rl="O", rc="C")
    # E=1.0, RL=0.95, RC=1.0 -> base*0.95
    assert temporal < base


def test_cvss31_environmental_requirements_raise_score():
    _, base = cvss31_base("N", "L", "N", "N", "U", "L", "N", "N")
    _, env = cvss31_environmental("N", "L", "N", "N", "U", "L", "N", "N",
                                  cr="H", ir="H", ar="H")
    assert env > base


def test_cvss31_environmental_modifies_metric():
    _, env_high = cvss31_environmental("N", "L", "N", "N", "U", "H", "H", "H")
    _, env_low = cvss31_environmental("N", "L", "N", "N", "U", "H", "H", "H",
                                      mc="N", mi="N", ma="N")
    assert env_low < env_high


def test_cvss31_environmental_vector_lists_modified_metrics():
    vec, _ = cvss31_environmental("N", "L", "N", "N", "U", "H", "H", "H",
                                  mav="A", cr="H")
    assert "/MAV:A" in vec and "/CR:H" in vec


# ---------------------------------------------------------------------------
# parse_vector
# ---------------------------------------------------------------------------
def test_parse_vector31_roundtrip():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    norm, score = parse_vector31(v)
    assert score == 9.8
    assert norm == v


def test_parse_vector31_normalizes_order():
    # out-of-order metrics are normalized
    v = "CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H/PR:N"
    norm, score = parse_vector31(v)
    assert score == 9.8
    assert norm == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_parse_vector31_with_temporal():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C"
    norm, score = parse_vector31(v)
    assert "/E:H/RL:O/RC:C" in norm
    assert score < 9.8


def test_parse_vector31_missing_metric_raises():
    with pytest.raises(ValueError):
        parse_vector31("CVSS:3.1/AV:N/AC:L")


def test_parse_vector31_bad_version_raises():
    with pytest.raises(ValueError):
        parse_vector31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_parse_vector_dispatches_version():
    _, s31 = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    _, s40 = parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
    assert s31 == 9.8
    assert s40 == 10.0


# ---------------------------------------------------------------------------
# CVSS 4.0
# ---------------------------------------------------------------------------
def test_cvss40_canonical_max():
    vec, score = cvss40_base("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H")
    assert score == 10.0
    assert vec.startswith("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/")


def test_cvss40_zero_impact():
    _, score = cvss40_base("N", "L", "N", "N", "N", "N", "N", "N", "N", "N", "N")
    assert score == 0.0


def test_cvss40_ordering():
    _, low = cvss40_base("P", "H", "P", "H", "A", "L", "N", "N", "N", "N", "N")
    _, high = cvss40_base("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H")
    assert low < high


def test_parse_vector40_roundtrip():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    norm, score = parse_vector40(v)
    assert score == 10.0
    assert norm == v


def test_parse_vector40_missing_metric_raises():
    with pytest.raises(ValueError):
        parse_vector40("CVSS:4.0/AV:N")


def test_severity_name_thresholds():
    assert severity_name(9.8) == "Critical"
    assert severity_name(7.5) == "High"
    assert severity_name(5.0) == "Medium"
    assert severity_name(1.0) == "Low"
    assert severity_name(0.0) == "None"


# ---------------------------------------------------------------------------
# categories.py integration (cvss_for uses the registry)
# ---------------------------------------------------------------------------
def test_category_defaults_via_report_cvss_for():
    from valen.redteam.report import cvss_for

    vec, score = cvss_for("idor")
    assert vec.startswith("CVSS:3.1/")
    assert 4.0 <= score < 9.0
    # alias resolves through the canonical registry to command_execution
    # (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8)
    vec2, score2 = cvss_for("cmdi")
    assert score2 >= 8.0
    assert "CVSS:3.1" in vec2


def test_cvss40_defaults_from_categories():
    from valen.categories import cvss40_for
    from valen.cvss import cvss40_base

    params = cvss40_for("command_execution")
    vec, score = cvss40_base(*params)
    assert score > 8.0
