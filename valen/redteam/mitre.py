"""MITRE ATT&CK tactic mapping for findings and attack-plan steps.

Maps a VALEN finding category (and an IAM relation) to a MITRE ATT&CK Enterprise
tactic, so a red-team plan can be ordered by kill-chain phase rather than by
severity string.
"""

from __future__ import annotations

from typing import Dict, Tuple

# ATT&CK tactic id -> display name (Enterprise).
_TACTIC_NAMES: Dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}

# category -> (tactic id, tactic name) — backed by the canonical
# ``valen.categories`` registry; kept here as a dict for backwards compatibility.
from .. import categories as _categories

CATEGORY_TACTICS: Dict[str, Tuple[str, str]] = {
    c.name: (c.mitre_tactic, _TACTIC_NAMES.get(c.mitre_tactic, c.mitre_tactic))
    for c in _categories.all_categories()
}

# IAM relation -> (tactic id, tactic name)
RELATION_TACTICS: Dict[str, Tuple[str, str]] = {
    "assume": ("TA0004", "Privilege Escalation"),
    "access": ("TA0008", "Lateral Movement"),
    "trust": ("TA0008", "Lateral Movement"),
}

# kill-chain phase order (for sorting a plan): ATT&CK tactic ids are not
# temporal, so we impose the actual recon -> escalate -> move -> collect order.
PHASE_ORDER = {
    "TA0001": 0,   # Initial Access
    "TA0007": 1,   # Discovery
    "TA0002": 2,   # Execution
    "TA0003": 3,   # Persistence
    "TA0004": 4,   # Privilege Escalation
    "TA0005": 5,   # Defense Evasion
    "TA0006": 6,   # Credential Access
    "TA0008": 7,   # Lateral Movement
    "TA0009": 8,   # Collection
    "TA0010": 9,   # Exfiltration
    "TA0011": 10,  # Command and Control
    "TA0040": 11,  # Impact
}


def tactic_for_category(category: str) -> Tuple[str, str]:
    return CATEGORY_TACTICS.get(category, ("TA0007", "Discovery"))


def tactic_for_relation(relation: str) -> Tuple[str, str]:
    return RELATION_TACTICS.get(relation, ("TA0008", "Lateral Movement"))


# ATT&CK technique id -> display name (the subset VALEN emits).
TECHNIQUE_NAMES: Dict[str, str] = {
    "T1046": "Network Service Scanning",
    "T1595.002": "Vulnerability Scanning",
    "T1592": "Gather Victim Host Information",
    "T1083": "File and Directory Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1190": "Exploit Public-Facing Application",
    "T1213": "Data from Information Repositories",
    "T1069.002": "Domain Groups",
    "T1098": "Account Manipulation",
    "T1098.005": "Device Registration",
    "T1222.001": "Windows File and Directory Permissions Modification",
    "T1484.001": "Group Policy Modification",
    "T1003.006": "DCSync",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.006": "Windows Remote Management",
    "T1134": "Access Token Manipulation",
    "T1555": "Credentials from Password Stores",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1558.004": "AS-REP Roasting",
    "T1552.006": "Group Policy Preferences",
    "T1482": "Domain Trust Discovery",
    "T1071": "Application Layer Protocol",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUE_NAMES.get(technique_id, technique_id)

