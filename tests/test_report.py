"""Tests for the report generator and CVSS scoring."""

from pathlib import Path


from valen.redteam.report import build_report, cvss_base, cvss_for, severity_name

ROOT = Path(__file__).resolve().parent.parent


def test_cvss_base_known_vector():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 (canonical)
    _, score = cvss_base("N", "L", "N", "N", "U", "H", "H", "H")
    assert score == 9.8


def test_cvss_base_ordering():
    _, low = cvss_base("N", "L", "L", "N", "U", "L", "N", "N")
    _, high = cvss_base("N", "L", "N", "N", "U", "H", "H", "H")
    assert low < high


def test_cvss_for_idor():
    vector, score = cvss_for("idor")
    assert vector.startswith("CVSS:3.1/")
    assert 4.0 <= score < 9.0


def test_severity_name():
    assert severity_name(9.8) == "Critical"
    assert severity_name(7.5) == "High"
    assert severity_name(5.0) == "Medium"
    assert severity_name(0.0) == "None"


def test_build_report_embeds_findings():
    data = {
        "findings": [{
            "title": "BOLA/IDOR: cross-user access", "category": "idor",
            "severity": "Medium", "cvss": 6.5, "vector": "CVSS:3.1/...",
            "repro": "GET /x", "evidence": "{}", "remediation": "fix",
        }],
        "plan_steps": [], "bola": {"recall": 1.0, "precision": 0.72},
        "recon_hosts": [{"ip": "127.0.0.1"}], "recon_cve_hints": [],
        "enum_shadow": ["/admin"],
    }
    html = build_report(data)
    assert "BOLA/IDOR: cross-user access" in html
    assert "CVSS:3.1/" in html
    assert "/admin" in html


def test_collect_report_data_runs():
    from valen.redteam.report import collect_report_data
    d = collect_report_data()
    assert isinstance(d["findings"], list)
    assert isinstance(d["plan_steps"], list)
