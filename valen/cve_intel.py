"""CVE intelligence: KEV / EPSS / product-version hints (offline snapshot).

Loads the bundled snapshot in ``benchmarks/cve_intel/`` and answers:

* ``lookup(cve_id)``           -> CVE record (CWE, CVSS, KEV, EPSS, description)
* ``enrich_findings(findings)``-> adds ``cve_ids`` / ``kev`` / ``epss`` per finding
* ``enrich_hints(hints)``      -> adds CVE ids to recon ``cve_hypotheses``
* ``version_hints(product, version)`` -> CVEs known for a product/version

The snapshot is refreshed with ``just cve-sync`` (or
``python benchmarks/cve_intel/build_snapshot.py``) which pulls CISA KEV,
FIRST.org EPSS and (optionally) the NVD API. Everything here works offline —
the snapshot is committed to the repo, so a red-teamer can generate a report on
an air-gapped engagement laptop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

INTEL_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "cve_intel"

_cves: Optional[Dict[str, Dict[str, Any]]] = None
_kev: Optional[Dict[str, Dict[str, Any]]] = None
_epss: Optional[Dict[str, float]] = None
_products: Optional[List[Dict[str, Any]]] = None


def _load(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _ensure() -> None:
    global _cves, _kev, _epss, _products
    if _cves is not None:
        return
    raw = _load(INTEL_DIR / "cves.json", [])
    _cves = {c["cve"]: c for c in raw if "cve" in c}
    _kev = {k["cve"]: k for k in _load(INTEL_DIR / "kev.json", []) if "cve" in k}
    _epss = {e["cve"]: float(e.get("epss", 0.0)) for e in _load(INTEL_DIR / "epss.json", [])}
    _products = _load(INTEL_DIR / "products.json", [])


def lookup(cve_id: str) -> Dict[str, Any]:
    """Full intelligence record for one CVE id (empty dict if unknown)."""
    _ensure()
    cid = cve_id.upper()
    base = dict(_cves.get(cid, {"cve": cid}))
    kev = _kev.get(cid)
    base["kev"] = bool(kev)
    if kev:
        base["kev_date_added"] = kev.get("date_added", "")
        base["kev_ransomware"] = bool(kev.get("ransomware_campaign", False))
    base["epss"] = _epss.get(cid, 0.0)
    return base


def all_cves() -> List[Dict[str, Any]]:
    _ensure()
    return [lookup(cid) for cid in sorted(_cves)]


def version_hints(product: str, version: str = "") -> List[str]:
    """CVE ids known for a product (and optional version)."""
    _ensure()
    prod = (product or "").lower()
    ver = (version or "").lower()
    out: List[str] = []
    for entry in _products:
        p = str(entry.get("product", "")).lower()
        if not p or p not in prod and prod not in p:
            continue
        entry_ver = str(entry.get("version", "")).lower()
        if entry_ver and ver and entry_ver not in ver and ver not in entry_ver:
            continue
        for c in entry.get("cves", []):
            if c not in out:
                out.append(c)
    return out


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach CVE / KEV / EPSS to each finding that matches the snapshot.

    Matching is by category → CVE keyword and by title/filename mention. The
    mapping is deliberately conservative: a finding is only annotated when the
    snapshot has an unambiguous match, never guessed.
    """
    _ensure()
    for f in findings:
        if f.get("cve_ids"):
            continue
        text = " ".join([
            str(f.get("title", "")), str(f.get("description", "")),
            str(f.get("repro", "")), str(f.get("sink_name", "")),
            str(f.get("file", "")),
        ]).lower()
        hits: List[str] = []
        for cid, rec in _cves.items():
            keys = [str(rec.get("cve", "")).lower()]
            keys += [str(x).lower() for x in rec.get("aliases", [])]
            keys += [str(rec.get("product", "")).lower()]
            for k in keys:
                if k and k in text and cid not in hits:
                    hits.append(cid)
        if hits:
            f["cve_ids"] = hits
            f["kev"] = any(_kev.get(h) for h in hits)
            f["epss"] = max(_epss.get(h, 0.0) for h in hits)
    return findings


def enrich_hints(hints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add resolved CVE ids to recon ``cve_hypotheses`` entries."""
    import re

    _ensure()
    for h in hints:
        if h.get("cve_ids"):
            continue
        text = (str(h.get("version", "")) + " " + str(h.get("hypothesis", ""))
                + " " + str(h.get("service", "")))
        cves = version_hints(str(h.get("service", "")) or text, text)
        # any CVE id already written in the hypothesis text
        for m in re.findall(r"CVE-\d{4}-\d+", text, flags=re.I):
            cid = m.upper()
            if cid not in cves:
                cves.append(cid)
        # any CVE id from the snapshot whose product is mentioned in the text
        low = text.lower()
        for cid, rec in _cves.items():
            prod = str(rec.get("product", "")).lower()
            if prod and prod in low and cid not in cves:
                cves.append(cid)
        if cves:
            h["cve_ids"] = cves
            h["kev"] = any(_kev.get(c) for c in cves)
            h["epss"] = max((_epss.get(c, 0.0) for c in cves), default=0.0)
    return hints
