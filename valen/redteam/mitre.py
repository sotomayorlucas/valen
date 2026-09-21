"""MITRE ATT&CK tactic mapping for findings and attack-plan steps.

Maps a VALEN finding category (and an IAM relation) to a MITRE ATT&CK Enterprise
tactic, so a red-team plan can be ordered by kill-chain phase rather than by
severity string.
"""

from __future__ import annotations

from typing import Dict, Tuple

# category -> (tactic id, tactic name)
CATEGORY_TACTICS: Dict[str, Tuple[str, str]] = {
    "idor": ("TA0009", "Collection"),
    "missing_authorization": ("TA0004", "Privilege Escalation"),
    "sql": ("TA0006", "Credential Access"),
    "command_execution": ("TA0002", "Execution"),
    "code_execution": ("TA0002", "Execution"),
    "deserialization": ("TA0002", "Execution"),
    "file_write": ("TA0002", "Execution"),
    "path_traversal": ("TA0006", "Credential Access"),
    "reentrancy": ("TA0040", "Impact"),
    "state_cycle": ("TA0040", "Impact"),
    "tool_misuse": ("TA0002", "Execution"),
    "lateral_movement": ("TA0008", "Lateral Movement"),
    "privilege_escalation": ("TA0004", "Privilege Escalation"),
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
