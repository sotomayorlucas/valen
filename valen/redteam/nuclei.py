"""nuclei integration: template-based verification of discovered services.

After recon surfaces hosts/services, nuclei confirms whether a known template
(CVE / misconfiguration / exposure) actually matches. This module builds the
command (stealth-aware) and parses its ``-jsonl`` output into VALEN findings,
tagged with a MITRE tactic.

For authorized engagements only.
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .mitre import tactic_for_category
from .stealth import StealthProfile

# severity -> (category, tactic) used to fold a nuclei finding into the plan
_SEVERITY_CATEGORY = {
    "critical": ("code_execution", "TA0002"),
    "high": ("code_execution", "TA0002"),
    "medium": ("sql", "TA0006"),
    "low": ("lateral_movement", "TA0007"),
    "info": ("lateral_movement", "TA0007"),
    "unknown": ("lateral_movement", "TA0007"),
}


def build_nuclei_args(
    targets: List[str],
    profile: Optional[StealthProfile] = None,
    template_dir: str = "",
    severities: str = "critical,high,medium",
    extra: Optional[List[str]] = None,
) -> List[str]:
    """Build a nuclei command with quiet/rate-limited (stealth) flags."""
    rate = (profile.max_rate if profile and profile.max_rate else 50)
    args = ["nuclei", "-silent", "-no-color", "-jsonl",
            "-rate-limit", str(rate), "-severity", severities]
    if profile and profile.host_timeout:
        args += ["-timeout", profile.host_timeout.replace("m", "")]  # nuclei wants seconds
    if template_dir:
        args += ["-t", template_dir]
    args += list(extra or [])
    args += ["-u"]
    args += targets
    return args


def parse_nuclei_json(text: str) -> List[Dict]:
    """Parse nuclei ``-jsonl`` output into a list of finding dicts."""
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        severity = (info.get("severity") or "unknown").lower()
        category, tactic_id = _SEVERITY_CATEGORY.get(severity, ("lateral_movement", "TA0007"))
        out.append({
            "template_id": obj.get("template-id", ""),
            "name": info.get("name", obj.get("template-id", "")),
            "severity": severity,
            "tags": info.get("tags", []),
            "host": obj.get("host", ""),
            "matched_at": obj.get("matched-at", ""),
            "category": category,
            "tactic_id": tactic_id,
        })
    return out


def to_plan_steps(findings: List[Dict]) -> List[Dict]:
    """Fold nuclei findings into attack-plan steps tagged with a tactic."""
    steps = []
    for f in findings:
        _, tname = tactic_for_category(f["category"])
        steps.append({
            "phase": "Execution" if f["tactic_id"] == "TA0002" else
                     ("Credential Access" if f["tactic_id"] == "TA0006" else "Discovery"),
            "tactic_id": f["tactic_id"],
            "tactic": tname,
            "title": f"{f['severity'].upper()} · {f['name']}",
            "detail": f"template {f['template_id']} matched at {f['matched_at']} "
                      f"(host {f['host']})",
        })
    return steps
