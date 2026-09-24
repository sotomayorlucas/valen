"""Canonical vulnerability-category registry.

One place to reason about a finding category: severity, CWE ids, OWASP Top-10
(2021) classification, default CVSS 3.1 / 4.0 vectors, MITRE ATT&CK tactic and
remediation guidance. Previously this knowledge was scattered across
``sources_sinks.CATEGORY_SEVERITY``, ``redteam.report._CVSS_BY_CATEGORY``,
``redteam.mitre.CATEGORY_TACTICS`` and the OWASP-Benchmark slug table in
``ingest.java``. All of those now read from here (or delegate to it), so a new
category is added in exactly one table.

Aliases (OWASP-Benchmark slugs like ``sqli`` / ``cmdi``) resolve to the same
``CategoryInfo`` as their canonical name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class CategoryInfo:
    """Everything we know about one vulnerability category."""

    name: str
    severity: str  # critical | high | medium | low | info
    cwe: Tuple[str, ...]  # ("CWE-78",)
    owasp: str  # "A03:2021 – Injection"
    # CVSS 3.1 base: (AV, AC, PR, UI, S, C, I, A)
    cvss31: Tuple[str, str, str, str, str, str, str, str]
    # CVSS 4.0 base: (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA)
    cvss40: Tuple[str, str, str, str, str, str, str, str, str, str, str]
    mitre_tactic: str  # "TA0002"
    remediation: str
    aliases: Tuple[str, ...] = ()


# CVSS 3.1 metric orders used in ``cvss31`` tuples.
CVSS31_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
# CVSS 4.0 base metric orders used in ``cvss40`` tuples.
CVSS40_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")


def _c31(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str):
    return (av, ac, pr, ui, s, c, i, a)


def _c40(av: str, ac: str, at: str, pr: str, ui: str,
         vc: str, vi: str, va: str, sc: str, si: str, sa: str):
    return (av, ac, at, pr, ui, vc, vi, va, sc, si, sa)


_CATEGORIES: Tuple[CategoryInfo, ...] = (
    # ---- injection / execution --------------------------------------------
    CategoryInfo(
        name="command_execution",
        severity="critical",
        cwe=("CWE-78",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Avoid shell interpretation of untrusted data. Use argument "
                    "arrays (subprocess list form), strict allow-lists and "
                    "shell-escaping as defense in depth.",
        aliases=("cmdi", "os_command_injection"),
    ),
    CategoryInfo(
        name="code_execution",
        severity="critical",
        cwe=("CWE-94", "CWE-95"),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Never eval/exec dynamic content. Replace with safe "
                    "interpreters (ast.literal_eval, JSON, safe templates).",
        aliases=("code_injection",),
    ),
    CategoryInfo(
        name="template_injection",
        severity="high",
        cwe=("CWE-1336", "CWE-94"),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Render untrusted data only as values, never as template "
                    "source. Use sandboxed template engines (SSTI-safe modes).",
        aliases=("ssti",),
    ),
    CategoryInfo(
        name="sql",
        severity="high",
        cwe=("CWE-89",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0006",
        remediation="Use parameterized queries / prepared statements; never "
                    "concatenate untrusted input into SQL.",
        aliases=("sqli", "sql_injection"),
    ),
    CategoryInfo(
        name="deserialization",
        severity="critical",
        cwe=("CWE-502",),
        owasp="A08:2021 – Software and Data Integrity Failures",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Prefer data-only formats (JSON) and integrity-protected "
                    "serialization. If binary deserialization is required, use "
                    "strict type allow-lists.",
    ),
    CategoryInfo(
        name="file_inclusion",
        severity="critical",
        cwe=("CWE-98",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0002",
        remediation="Map inclusion targets against a fixed allow-list of "
                    "templates/files; reject any path with '..' or NUL bytes.",
        aliases=("lfi", "rfi"),
    ),
    # ---- memory safety ----------------------------------------------------
    CategoryInfo(
        name="buffer_overflow",
        severity="high",
        cwe=("CWE-120", "CWE-787"),
        owasp="A06:2021 – Vulnerable and Outdated Components",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Use bounded copies (strncpy/snprintf with explicit NUL), "
                    "size every destination buffer, and enable stack canaries "
                    "+ ASLR/PIE.",
    ),
    CategoryInfo(
        name="format_string",
        severity="high",
        cwe=("CWE-134",),
        owasp="A06:2021 – Vulnerable and Outdated Components",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Never pass untrusted input as the format string. Use "
                    "constant formats (``printf(\"%s\", s)``).",
    ),
    CategoryInfo(
        name="memory_unsafe",
        severity="high",
        cwe=("CWE-119", "CWE-476"),
        owasp="A06:2021 – Vulnerable and Outdated Components",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Prefer memory-safe languages or safe wrappers; bound all "
                    "copies and audit raw pointer arithmetic / free()s.",
    ),
    # ---- access control ---------------------------------------------------
    CategoryInfo(
        name="path_traversal",
        severity="high",
        cwe=("CWE-22",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0006",
        remediation="Resolve the final path (realpath) and require it to stay "
                    "under an allowed root; reject '..' segments.",
    ),
    CategoryInfo(
        name="file_write",
        severity="medium",
        cwe=("CWE-73", "CWE-434"),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0002",
        remediation="Do not let untrusted input choose output paths; validate "
                    "extensions and store under a generated, non-guessable name.",
    ),
    CategoryInfo(
        name="idor",
        severity="medium",
        cwe=("CWE-639",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0009",
        remediation="Enforce object-level authorization (ownership) on every "
                    "resource identifier, server-side.",
        aliases=("bola", "insecure_direct_object_reference"),
    ),
    CategoryInfo(
        name="missing_authorization",
        severity="high",
        cwe=("CWE-862",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0004",
        remediation="Add an explicit authorization check on every state-"
                    "changing or data-revealing endpoint; default deny.",
        aliases=("bfla", "missing_auth"),
    ),
    CategoryInfo(
        name="account_takeover",
        severity="high",
        cwe=("CWE-287", "CWE-347"),
        owasp="A07:2021 – Identification and Authentication Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0006",
        remediation="Pin the signature algorithm, verify signatures on every "
                    "token, and reject alg=none / key-confusion.",
    ),
    CategoryInfo(
        name="privilege_escalation",
        severity="high",
        cwe=("CWE-269",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0004",
        remediation="Apply least privilege and enforce the permission boundary "
                    "at every trust transition (assume-role, admin flag, etc).",
    ),
    # ---- smart contracts --------------------------------------------------
    CategoryInfo(
        name="reentrancy",
        severity="high",
        cwe=("CWE-841",),
        owasp="A04:2021 – Insecure Design",
        cvss31=_c31("N", "H", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "H", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0040",
        remediation="Follow checks-effects-interactions: update state before "
                    "external calls, or use a reentrancy guard.",
    ),
    CategoryInfo(
        name="state_cycle",
        severity="high",
        cwe=("CWE-372",),
        owasp="A04:2021 – Insecure Design",
        cvss31=_c31("N", "H", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "H", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0040",
        remediation="Model the state machine explicitly and forbid "
                    "inconsistent transitions (freeze/withdraw races).",
    ),
    # ---- information disclosure / ops ------------------------------------
    CategoryInfo(
        name="logging",
        severity="medium",
        cwe=("CWE-532", "CWE-117"),
        owasp="A09:2021 – Security Logging and Monitoring Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0007",
        remediation="Redact secrets/tokens before logging; sanitize newlines "
                    "to prevent log forging.",
    ),
    CategoryInfo(
        name="network",
        severity="medium",
        cwe=("CWE-319", "CWE-941"),
        owasp="A02:2021 – Cryptographic Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0011",
        remediation="Use TLS for all endpoints; do not send secrets in clear "
                    "text or to untrusted hosts.",
    ),
    CategoryInfo(
        name="tool_misuse",
        severity="high",
        cwe=("CWE-676",),
        owasp="A08:2021 – Software and Data Integrity Failures",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0002",
        remediation="Replace dangerous APIs (popen/system) with safe wrappers; "
                    "never invoke interpreters on untrusted scripts.",
    ),
    CategoryInfo(
        name="lateral_movement",
        severity="high",
        cwe=("CWE-284",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0008",
        remediation="Segment trust zones; require re-authentication at every "
                    "boundary crossing and scope credentials tightly.",
    ),
    # ---- OWASP-Benchmark property categories ------------------------------
    CategoryInfo(
        name="crypto",
        severity="medium",
        cwe=("CWE-327",),
        owasp="A02:2021 – Cryptographic Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0006",
        remediation="Use modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305); "
                    "avoid DES/RC4/Blowfish and ECB mode.",
        aliases=("weak_crypto",),
    ),
    CategoryInfo(
        name="hash",
        severity="medium",
        cwe=("CWE-328",),
        owasp="A02:2021 – Cryptographic Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0006",
        remediation="Use SHA-256+ for integrity and a password KDF "
                    "(argon2/bcrypt/scrypt) for credentials; never MD5/SHA-1.",
        aliases=("weak_hash",),
    ),
    CategoryInfo(
        name="weakrand",
        severity="medium",
        cwe=("CWE-338",),
        owasp="A02:2021 – Cryptographic Failures",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0006",
        remediation="Use a CSPRNG (secrets module, SecureRandom) for tokens, "
                    "passwords and nonces.",
        aliases=("weak_randomness",),
    ),
    CategoryInfo(
        name="securecookie",
        severity="low",
        cwe=("CWE-614", "CWE-1004"),
        owasp="A05:2021 – Security Misconfiguration",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0007",
        remediation="Set Secure and HttpOnly (and SameSite) on session "
                    "cookies; enforce HSTS.",
    ),
    CategoryInfo(
        name="xss",
        severity="medium",
        cwe=("CWE-79",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "N", "R", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "P", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0002",
        remediation="Context-aware output encoding (HTML/attr/JS/URL) and a "
                    "strict Content-Security-Policy.",
    ),
    CategoryInfo(
        name="ldapi",
        severity="high",
        cwe=("CWE-90",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0006",
        remediation="Escape/encode untrusted input for LDAP filters; prefer "
                    "parameterized queries where the library supports them.",
    ),
    CategoryInfo(
        name="xpathi",
        severity="high",
        cwe=("CWE-643",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0006",
        remediation="Use parameterized XPath queries; never concatenate "
                    "untrusted input into the XPath expression.",
    ),
    CategoryInfo(
        name="trustbound",
        severity="medium",
        cwe=("CWE-501",),
        owasp="A04:2021 – Insecure Design",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0004",
        remediation="Do not trust data crossing a privilege boundary; "
                    "re-validate at every layer.",
    ),
    CategoryInfo(
        name="open_redirect",
        severity="medium",
        cwe=("CWE-601",),
        owasp="A01:2021 – Broken Access Control",
        cvss31=_c31("N", "L", "N", "R", "U", "L", "N", "N"),
        cvss40=_c40("N", "L", "N", "N", "P", "L", "L", "N", "L", "L", "N"),
        mitre_tactic="TA0009",
        remediation="Allow-list redirect targets or use server-side IDs for "
                    "redirect destinations.",
    ),
    CategoryInfo(
        name="ssrf",
        severity="high",
        cwe=("CWE-918",),
        owasp="A10:2021 – Server-Side Request Forgery",
        cvss31=_c31("N", "L", "N", "N", "U", "H", "H", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "H", "H", "N", "H", "H", "N"),
        mitre_tactic="TA0008",
        remediation="Allow-list outbound destinations and block private "
                    "ranges/metadata IPs at the network layer.",
    ),
    CategoryInfo(
        name="nosql_injection",
        severity="high",
        cwe=("CWE-943",),
        owasp="A03:2021 – Injection",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "H", "H"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "H", "H", "H", "H", "H"),
        mitre_tactic="TA0006",
        remediation="Use query builders / parameterized APIs and reject "
                    "operator objects (``$gt``, ``$ne``) from user input.",
        aliases=("nosqli",),
    ),
    CategoryInfo(
        name="mass_assignment",
        severity="medium",
        cwe=("CWE-915",),
        owasp="A04:2021 – Insecure Design",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0004",
        remediation="Bind request bodies to explicit allow-listed fields; "
                    "never assign raw JSON to models with privileged attrs.",
    ),
    CategoryInfo(
        name="rate_limit",
        severity="medium",
        cwe=("CWE-770",),
        owasp="A04:2021 – Insecure Design",
        cvss31=_c31("N", "L", "N", "N", "U", "L", "L", "N"),
        cvss40=_c40("N", "L", "N", "N", "N", "L", "L", "L", "L", "L", "N"),
        mitre_tactic="TA0006",
        remediation="Enforce per-identity/per-IP rate limits and lockouts on "
                    "sensitive actions (login, OTP, coupon).",
    ),
    CategoryInfo(
        name="generic",
        severity="medium",
        cwe=("CWE-0",),
        owasp="Unmapped",
        cvss31=_c31("N", "L", "L", "N", "U", "H", "N", "N"),
        cvss40=_c40("N", "L", "N", "L", "N", "H", "L", "N", "H", "L", "N"),
        mitre_tactic="TA0007",
        remediation="Review the finding and apply vendor guidance.",
    ),
)

# name/alias -> CategoryInfo
_BY_NAME: Dict[str, CategoryInfo] = {}
for _cat in _CATEGORIES:
    _BY_NAME[_cat.name] = _cat
    for _alias in _cat.aliases:
        _BY_NAME[_alias] = _cat


def get(category: str) -> CategoryInfo:
    """Look up a category by canonical name or alias (falls back to generic)."""
    if category in _BY_NAME:
        return _BY_NAME[category]
    return _BY_NAME["generic"]


def resolve_name(category: str) -> str:
    """Return the canonical name for a category/alias."""
    return get(category).name


def all_categories() -> List[CategoryInfo]:
    return list(_CATEGORIES)


def severity_for(category: str) -> str:
    return get(category).severity


def cwe_for(category: str) -> Tuple[str, ...]:
    return get(category).cwe


def owasp_for(category: str) -> str:
    return get(category).owasp


def remediation_for(category: str) -> str:
    return get(category).remediation


def cvss31_for(category: str) -> Tuple[str, str, str, str, str, str, str, str]:
    return get(category).cvss31


def cvss40_for(category: str) -> Tuple[str, str, str, str, str, str, str, str, str, str, str]:
    return get(category).cvss40


def mitre_for(category: str) -> str:
    return get(category).mitre_tactic


def aliases_for(category: str) -> Tuple[str, ...]:
    return get(category).aliases
