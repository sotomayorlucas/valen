"""Active Directory attack-graph analysis for VALEN.

    from valen.redteam.ad import parse_sharphound, attack_plan
    ad = parse_sharphound(json.load(open("sharphound.json")))
    plan = attack_plan(ad, entries=["JDOE"])

Ingest BloodHound/SharpHound JSON, rank tier-0 reachability paths (Z3-confirmed)
and surface Kerberoastable / AS-REP-roastable accounts and GPP passwords. For
authorized engagements only.
"""

from .attacks import (
    asrep_command,
    attack_plan,
    crack_command,
    decrypt_cpassword,
    gpp_from_xml,
    kerberoast_command,
    spray_command,
)
from .collect import (
    asrep_roastable,
    build_graph,
    kerberoastable,
    parse_sharphound,
    parse_sharphound_json,
    privileged_users,
)
from .graph import ADGraph, RELATION_META, node_id
from .live import bloodhound_command, collect, parse_collection_dir
from .paths import attack_paths, betweenness_ranking, high_value_targets

__all__ = [
    "ADGraph",
    "RELATION_META",
    "node_id",
    "build_graph",
    "parse_sharphound",
    "parse_sharphound_json",
    "kerberoastable",
    "asrep_roastable",
    "privileged_users",
    "attack_paths",
    "high_value_targets",
    "betweenness_ranking",
    "attack_plan",
    "kerberoast_command",
    "asrep_command",
    "spray_command",
    "crack_command",
    "decrypt_cpassword",
    "gpp_from_xml",
    "bloodhound_command",
    "collect",
    "parse_collection_dir",
]
