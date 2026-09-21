"""H4 operationalization: authorization-invariant violations.

The review pointed out that "a vulnerability is a violation of an authorization
invariant" needs a *constructive* rule. Here it is:

* A privilege boundary is an ``auth`` edge (from a decorator/function such as
  ``login_required``) attached to a function. The IR encodes this as a ``gate``
  node with an ``auth`` edge into the function.
* A taint finding is an **authorization-invariant violation** iff its sink lies
  inside a function that is behind an auth gate: untrusted data reaches a
  protected region without the boundary neutralizing it.
"""

from __future__ import annotations

from typing import List, Optional

from ..ir import Graph, NodeKind
from .taint import Finding


def enclosing_function(graph: Graph, line: int) -> Optional[object]:
    """Return the FUNCTION node whose line span contains ``line`` (innermost)."""
    best = None
    for n in graph.nodes:
        if n.kind == NodeKind.FUNCTION and n.line <= line <= n.end_line:
            if best is None or (n.end_line - n.line) < (best.end_line - best.line):
                best = n
    return best


def auth_gates_for(graph: Graph, line: int) -> List[str]:
    """Return the auth-gate names guarding the function containing ``line``."""
    fn = enclosing_function(graph, line)
    if fn is None:
        return []
    return list(fn.attrs.get("auth", []))


def annotate_findings(graph: Graph, findings: List[Finding]) -> List[Finding]:
    """Populate ``finding.auth_gates`` for every taint finding (H4 tagging)."""
    for finding in findings:
        finding.auth_gates = auth_gates_for(graph, finding.line)
    return findings


def authorization_violations(graph: Graph, findings: List[Finding]) -> List[Finding]:
    """The subset of findings that cross a privilege boundary."""
    return [f for f in annotate_findings(graph, findings) if f.auth_gates]


naturality_violations = authorization_violations  # deprecated alias (pre-rename)
