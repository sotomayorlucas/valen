"""Tests for CVE intelligence (offline KEV/EPSS snapshot + enrichment)."""

from valen import cve_intel


def test_snapshot_loads():
    assert cve_intel.all_cves(), "snapshot must contain at least one CVE"
    assert cve_intel.lookup("CVE-2022-28346")["cve"] == "CVE-2022-28346"


def test_lookup_kev_cve():
    rec = cve_intel.lookup("CVE-2022-28346")
    assert rec["kev"] is True
    assert rec["epss"] > 0.5
    assert "CWE-89" in rec["cwe"]
    assert rec["cvss_score"] >= 9.0


def test_lookup_non_kev_cve():
    rec = cve_intel.lookup("CVE-2026-54569")
    assert rec["kev"] is False
    assert 0 <= rec["epss"] <= 1


def test_lookup_unknown_cve_is_safe():
    rec = cve_intel.lookup("CVE-1999-0000")
    assert rec["cve"] == "CVE-1999-0000"
    assert rec["kev"] is False


def test_version_hints():
    assert "CVE-2021-41773" in cve_intel.version_hints("Apache httpd", "2.4.49")
    assert "CVE-2011-2523" in cve_intel.version_hints("vsftpd", "2.3.4")
    assert cve_intel.version_hints("Nonexistent", "9.9") == []


def test_enrich_findings_by_product_mention():
    findings = [{
        "title": "SQL injection in Django queryset",
        "category": "sql",
        "description": "django/db/models/sql/query.py concatenates user input",
    }]
    out = cve_intel.enrich_findings([dict(f) for f in findings])
    assert out[0]["cve_ids"], "django finding must be annotated with CVEs"
    assert out[0]["kev"] is True  # CVE-2022-28346 is on the KEV catalog


def test_enrich_findings_no_guess():
    findings = [{
        "title": "unrelated finding",
        "category": "idor",
        "description": "user 1 reads user 2 object",
    }]
    out = cve_intel.enrich_findings([dict(f) for f in findings])
    assert not out[0].get("cve_ids"), "must not guess CVEs without evidence"


def test_enrich_hints_from_version_table():
    hints = [{"host": "10.0.0.5", "port": 80,
              "version": "Apache httpd 2.4.49",
              "hypothesis": "CVE-2021-41773 (path traversal)"}]
    out = cve_intel.enrich_hints([dict(h) for h in hints])
    assert out[0]["cve_ids"]
    assert "CVE-2021-41773" in out[0]["cve_ids"]


def test_enrich_hints_stays_clean_without_match():
    hints = [{"host": "10.0.0.9", "port": 1,
              "version": "AcmeServer 1.0", "hypothesis": "unknown"}]
    out = cve_intel.enrich_hints([dict(h) for h in hints])
    assert not out[0].get("cve_ids")


def test_report_carries_cve_enrichment():
    from valen.redteam.report import build_json, collect_report_data

    d = collect_report_data()
    # the recon hints in the committed snapshot must be enriched
    enriched = [h for h in d["recon_cve_hints"] if h.get("cve_ids")]
    assert enriched, "recon hints must carry CVE ids after enrichment"
    body = build_json(d)
    assert "CVE-" in body or '"cve_ids": []' in body


def test_sarif_carries_cve_properties():
    import json

    from valen.redteam.report import build_sarif, collect_report_data

    d = collect_report_data()
    sarif = json.loads(build_sarif(d))
    props = sarif["runs"][0]["results"][0]["properties"]
    for key in ("cvss_vector", "cvss_score", "cwe", "owasp", "mitre_tactic",
                "cve_ids", "kev", "epss", "remediation"):
        assert key in props
