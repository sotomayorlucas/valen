"""Refresh the CVE intelligence snapshot (KEV + EPSS + NVD).

Run with network access:

    python benchmarks/cve_intel/build_snapshot.py
    # or: just cve-sync

Pulls:

* CISA KEV catalog        https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
* FIRST.org EPSS          https://api.first.org/data/v1/epss
* NVD CVE API 2.0         https://services.nvd.nist.gov/rest/json/cves/2.0

and writes ``cves.json`` / ``kev.json`` / ``epss.json`` / ``products.json`` in
this directory. Without network the script exits non-zero and leaves the
committed snapshot untouched — analysis and reporting keep working offline.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List

INTEL = Path(__file__).resolve().parent
REPO = INTEL.parents[1]

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def _get(url: str, timeout: int = 20) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "valen/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def sync_kev() -> List[Dict[str, Any]]:
    data = _get(KEV_URL)
    out = []
    for v in data.get("vulnerabilities", []):
        out.append({
            "cve": v.get("cveID", ""),
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware_campaign": bool(v.get("knownRansomwareCampaignUse", "") == "Known"),
            "required_action": v.get("requiredAction", ""),
        })
    return out


def sync_epss(cve_ids: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    # FIRST API accepts a comma-separated cveId list (chunked).
    for i in range(0, len(cve_ids), 50):
        chunk = ",".join(cve_ids[i:i + 50])
        data = _get(f"{EPSS_URL}?cveId={chunk}")
        for row in data.get("data", []):
            out.append({
                "cve": row.get("cve", ""),
                "epss": float(row.get("epss", 0.0)),
                "percentile": float(row.get("percentile", 0.0)),
            })
    return out


def sync_nvd(cve_id: str) -> Dict[str, Any]:
    try:
        data = _get(f"{NVD_URL}{cve_id}")
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        vec, score = "", 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                vec = m.get("vectorString", "")
                score = float(m.get("baseScore", 0.0))
                break
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-") and d["value"] not in cwes:
                    cwes.append(d["value"])
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        return {"cwe": cwes or ["CWE-0"], "cvss_vector": vec,
                "cvss_score": score, "description": desc}
    except Exception:
        return {}


def main() -> int:
    cases_path = REPO / "benchmarks" / "cve_cases.json"
    if not cases_path.exists():
        print("error: benchmarks/cve_cases.json not found", file=sys.stderr)
        return 1
    cases = json.loads(cases_path.read_text())
    cve_ids = [c["cve"] for c in cases]

    try:
        kev = sync_kev()
    except Exception as exc:  # noqa: BLE001
        print(f"error: KEV fetch failed ({exc}); snapshot untouched", file=sys.stderr)
        return 1
    try:
        epss = sync_epss(cve_ids)
    except Exception as exc:  # noqa: BLE001
        print(f"warn: EPSS fetch failed ({exc}); keeping prior EPSS", file=sys.stderr)
        epss = []

    # Preserve the curated cves.json (product/cwe/cvss annotations) and refresh
    # only the fields NVD is authoritative for.
    prior = json.loads((INTEL / "cves.json").read_text()) if (INTEL / "cves.json").exists() else []
    prior_by_id = {r["cve"]: r for r in prior}

    cves = []
    for cid in cve_ids:
        rec = dict(prior_by_id.get(cid, {"cve": cid}))
        nvd = sync_nvd(cid)
        if nvd:
            rec["cwe"] = nvd.get("cwe", rec.get("cwe", ["CWE-0"]))
            if nvd.get("cvss_vector"):
                rec["cvss_vector"] = nvd["cvss_vector"]
            if nvd.get("cvss_score"):
                rec["cvss_score"] = nvd["cvss_score"]
            if nvd.get("description"):
                rec["description"] = nvd["description"]
        rec.setdefault("cwe", ["CWE-0"])
        rec.setdefault("cvss_vector", "")
        rec.setdefault("cvss_score", 0.0)
        rec.setdefault("description", "")
        rec.setdefault("product", "")
        rec.setdefault("repo", "")
        rec.setdefault("aliases", [])
        cves.append(rec)

    (INTEL / "kev.json").write_text(json.dumps(kev, indent=2))
    if epss:
        (INTEL / "epss.json").write_text(json.dumps(epss, indent=2))
    (INTEL / "cves.json").write_text(json.dumps(cves, indent=2))
    print(f"cve-sync: {len(cves)} cves, {len(kev)} KEV, {len(epss)} EPSS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
