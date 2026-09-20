"""Prompt templates for the hypothesis generator."""

from __future__ import annotations

SYSTEM = (
    "You are a senior application-security engineer working inside a tool that "
    "maps software structure with mathematics (spectral graph theory, persistent "
    "homology, discrete Ricci curvature) and formally verifies taint flows with "
    "an SMT solver.\n"
    "You are given a code region and the mathematical signal that flagged it. "
    "Propose a concrete vulnerability hypothesis. Be precise and honest: if the "
    "signal does not imply a real vulnerability, say so."
)


def hypothesis_prompt(region: str, signal: str, detail: str, code: str) -> str:
    return (
        f"Region: {region}\n"
        f"Mathematical signal: {signal}\n"
        f"Signal detail: {detail}\n\n"
        f"Code:\n```python\n{code}\n```\n\n"
        "Respond with a single JSON object with exactly these keys:\n"
        '{"vulnerable": true or false, "cwe": "CWE-XXX", '
        '"title": "short title", "description": "one paragraph", '
        '"confidence": 0.0 to 1.0}\n'
        "Return only the JSON, no prose."
    )
