"""Active Directory attack-graph model.

Builds a VALEN IR graph from AD objects (users / groups / computers / domains /
GPOs / OUs). Principals are ``GATE`` nodes (privilege boundaries); relations are
``CALL`` edges with an ``attrs["relation"]`` bucket (``assume`` / ``access`` /
``trust``) so the existing escalation-chain + Z3 + MITRE machinery applies
unchanged.

BloodHound semantics:
* ``MemberOf``  user/computer/group -> group
* ACL edges     GenericAll / WriteDacl / WriteOwner / ForceChangePassword /
                AddKeyCredentialLink / AllExtendedRights / Owns / DCSync / GPLink
* ``AdminTo``   principal -> computer (local admin)
* ``HasSession``user -> computer (active session)
* ``TrustedBy`` domain -> domain
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ...ir import EdgeKind, Graph, NodeKind

# AD relation -> (bucket, MITRE technique, tactic id)
RELATION_META: Dict[str, Tuple[str, str, str]] = {
    "MemberOf": ("assume", "T1069.002", "TA0004"),
    "GenericAll": ("assume", "T1098", "TA0004"),
    "GenericWrite": ("assume", "T1098", "TA0004"),
    "WriteDacl": ("assume", "T1222.001", "TA0004"),
    "WriteOwner": ("assume", "T1222.001", "TA0004"),
    "Owns": ("assume", "T1098", "TA0004"),
    "ForceChangePassword": ("assume", "T1098", "TA0004"),
    "AddKeyCredentialLink": ("assume", "T1098.005", "TA0004"),
    "AllExtendedRights": ("assume", "T1098", "TA0004"),
    "DCSync": ("assume", "T1003.006", "TA0006"),
    "GPLink": ("assume", "T1484.001", "TA0004"),
    "AdminTo": ("access", "T1021.002", "TA0008"),
    "HasSession": ("access", "T1021.001", "TA0008"),
    "CanRDP": ("access", "T1021.001", "TA0008"),
    "CanPSRemote": ("access", "T1021.006", "TA0008"),
    "ExecuteAsUser": ("access", "T1134", "TA0004"),
    "ReadLAPSPassword": ("access", "T1555", "TA0006"),
    "ReadGMSAPassword": ("access", "T1555", "TA0006"),
    "AllowedToDelegate": ("trust", "T1558", "TA0008"),
    "TrustedBy": ("trust", "T1482", "TA0008"),
}

# ACL rights recognised as edges.
ACL_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "ForceChangePassword", "AddKeyCredentialLink", "AllExtendedRights",
    "DCSync", "ReadLAPSPassword", "ReadGMSAPassword",
}

KIND_OF = {"user": "user", "group": "group", "computer": "computer",
           "domain": "domain", "gpo": "gpo", "ou": "ou"}


def node_id(kind: str, name: str) -> str:
    return f"{kind}:{(name or '').upper()}"


def _rel(relation: str) -> Tuple[str, str, str]:
    return RELATION_META.get(relation, ("assume", "T1069", "TA0004"))


class ADGraph:
    """Accumulator that turns AD records into a typed IR graph."""

    def __init__(self) -> None:
        self.graph = Graph()
        self.graph.meta = {"language": "ad", "domain": ""}
        self.sid_to_id: Dict[str, str] = {}
        self.records: Dict[str, List[Dict[str, Any]]] = {
            "users": [], "groups": [], "computers": [], "domains": [],
            "gpos": [], "ous": [],
        }

    # -- nodes -------------------------------------------------------------
    def add_principal(self, kind: str, name: str, domain: str = "",
                      attrs: Optional[Dict[str, Any]] = None,
                      sid: str = "") -> str:
        nid = node_id(kind, name)
        a = {"ad_kind": kind, "domain": domain}
        if attrs:
            a.update(attrs)
        if not self.graph.has_node(nid):
            self.graph.add_node(nid, NodeKind.GATE, name, attrs=a)
        if sid:
            self.sid_to_id.setdefault(sid, nid)
        return nid

    def add_edge(self, src: str, dst: str, relation: str) -> None:
        if not src or not dst or src == dst:
            return
        bucket, technique, tactic = _rel(relation)
        self.graph.add_edge(src, dst, EdgeKind.CALL,
                            attrs={"relation": bucket, "ad_relation": relation,
                                   "technique": technique, "tactic_id": tactic})

    def resolve_sid(self, sid: str) -> Optional[str]:
        return self.sid_to_id.get(sid)
