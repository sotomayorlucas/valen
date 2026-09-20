"""Autonomous LLM agent that navigates the vulnerability manifold.

The agent closes the loop the whitepaper describes:

    map -> rank -> hypothesize -> verify -> report

It is designed to run *offline* (deterministic heuristic hypotheses) when no LLM
is configured, and to use a LiteLLM-backed model when one is available. The LLM
proposes hypotheses; the formal layer (Z3 / taint / topology) proves or refutes
them.
"""

from .agent import ManifoldAgent, Report, ReportEntry

__all__ = ["ManifoldAgent", "Report", "ReportEntry"]
