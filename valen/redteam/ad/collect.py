"""Ingest Active Directory collection output (BloodHound / SharpHound JSON).

Parses the legacy SharpHound JSON (``users``/``groups``/``computers``/``domains``
/``gpos``/``ous``) into an :class:`ADGraph`. Also exposes the normalized
``records`` used by the credential-attack helpers (Kerberoastable / AS-REP).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .graph import ACL_RIGHTS, ADGraph


def _props(obj: Dict[str, Any]) -> Dict[str, Any]:
    return obj.get("Properties", obj) or {}


def _name(props: Dict[str, Any]) -> str:
    return props.get("name") or props.get("samaccountname") or props.get("distinguishedname", "")


def _sid(obj: Dict[str, Any]) -> str:
    return obj.get("ObjectIdentifier") or _props(obj).get("objectid", "")


def build_graph(data: Dict[str, Any]) -> ADGraph:
    ad = ADGraph()
    ad.graph.meta["domain"] = (
        (_props(data["domains"][0]).get("name") if data.get("domains") else "") or ""
    )

    # pass 1: nodes
    for kind in ("users", "groups", "computers", "domains", "gpos", "ous"):
        singular = kind[:-1] if kind.endswith("s") else kind
        for obj in data.get(kind, []) or []:
            p = _props(obj)
            name = _name(p)
            domain = p.get("domain", "")
            attrs = {
                "enabled": bool(p.get("enabled", True)),
                "admincount": bool(p.get("admincount", False)),
                "hasspn": bool(p.get("hasspn", False)),
                "dontreqpreauth": bool(p.get("dontreqpreauth", False)),
                "operatingsystem": p.get("operatingsystem", ""),
                "haslaps": bool(p.get("haslaps", False)),
                "description": p.get("description", ""),
                "dn": p.get("distinguishedname", ""),
            }
            ad.add_principal(singular, name, domain, attrs, sid=_sid(obj))
            ad.records[kind].append({
                "name": name, "domain": domain, "sid": _sid(obj),
                "dn": p.get("distinguishedname", ""), **attrs,
            })

    # pass 2: edges
    for obj in data.get("groups", []) or []:
        gid = ad.resolve_sid(_sid(obj)) or ad.add_principal("group", _name(_props(obj)))
        for m in obj.get("Members", []) or []:
            member = ad.resolve_sid(m.get("ObjectIdentifier", ""))
            if member:
                ad.add_edge(member, gid, "MemberOf")

    for kind in ("users", "groups", "computers", "domains", "gpos", "ous"):
        for obj in data.get(kind, []) or []:
            owner = ad.resolve_sid(_sid(obj))
            if owner is None:
                continue
            for ace in obj.get("Aces", []) or []:
                right = ace.get("RightName", "")
                if right not in ACL_RIGHTS:
                    continue
                principal = ad.resolve_sid(ace.get("PrincipalSID", ""))
                if principal:
                    ad.add_edge(principal, owner, right)
            for la in obj.get("LocalAdmins", []) or []:
                admin = ad.resolve_sid(la.get("ObjectIdentifier", ""))
                if admin:
                    ad.add_edge(admin, owner, "AdminTo")
            for s in obj.get("Sessions", []) or []:
                u = ad.resolve_sid(s.get("UserSID", ""))
                c = ad.resolve_sid(s.get("ComputerSID", ""))
                if u and c:
                    ad.add_edge(u, c, "HasSession")
            for d in (obj.get("AllowedToAct", []) or []) + (obj.get("AllowedToDelegate", []) or []):
                dst = ad.resolve_sid(d.get("ObjectIdentifier", ""))
                if dst:
                    ad.add_edge(owner, dst, "AllowedToDelegate")

    for dom in data.get("domains", []) or []:
        did = ad.resolve_sid(_sid(dom))
        if did is None:
            continue
        for t in dom.get("Trusts", []) or []:
            tname = t.get("TargetDomainName") or t.get("TargetDomainSid", "")
            target = ad.add_principal("domain", tname)
            ad.add_edge(did, target, "TrustedBy")
        for link in dom.get("Links", []) or []:
            gpo = ad.resolve_sid(link.get("GUID", "")) or ad.add_principal("gpo", link.get("GUID", ""))
            ad.add_edge(gpo, did, "GPLink")

    return ad


def parse_sharphound(data: Dict[str, Any]) -> ADGraph:
    return build_graph(data)


def parse_sharphound_json(text: str) -> ADGraph:
    return build_graph(json.loads(text))


# -- credential-attack selection -------------------------------------------
def kerberoastable(ad: ADGraph) -> List[Dict[str, Any]]:
    """Enabled users holding an SPN (Kerberoastable)."""
    return [u for u in ad.records["users"] if u.get("enabled") and u.get("hasspn")]


def asrep_roastable(ad: ADGraph) -> List[Dict[str, Any]]:
    """Enabled users with Kerberos pre-auth disabled (AS-REP roastable)."""
    return [u for u in ad.records["users"] if u.get("enabled") and u.get("dontreqpreauth")]


def privileged_users(ad: ADGraph) -> List[Dict[str, Any]]:
    """Users flagged ``admincount`` (tier-0 / protected accounts)."""
    return [u for u in ad.records["users"] if u.get("admincount")]
