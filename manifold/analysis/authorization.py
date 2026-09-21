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


# ---------------------------------------------------------------------------
# Trust & logic pivot: BOLA / IDOR and missing-authorization (CWE-639/862)
# ---------------------------------------------------------------------------

# Sinks that *access or mutate* a resource (data store, filesystem, process).
RESOURCE_SINK_CATEGORIES = {
    "sql",
    "file_write",
    "path_traversal",
    "deserialization",
    "command_execution",
}

_HTTP_SOURCE_HINTS = ("http", "query", "form", "cookie", "json")


def _is_http_source(node) -> bool:
    """True for an untrusted HTTP-request source (a user-controlled selector).

    Excludes plain function parameters: for BOLA/IDOR the relevant signal is a
    *web* input (query/form/json/cookie), which may reach the sink through a
    cast (e.g. ``int(request.args.get("id"))``) that classic taint analysis
    treats as clean and therefore cannot flag.
    """
    if node.kind != NodeKind.SOURCE:
        return False
    desc = node.attrs.get("description", "").lower()
    if "function parameter" in desc:
        return False
    label = node.label.lower()
    if any(h in desc for h in _HTTP_SOURCE_HINTS):
        return True
    return label.startswith(("request.", "self.request", "req.", "flask.request", "django.http"))


def _fn_span(fn) -> tuple:
    lo = fn.line
    hi = fn.end_line if fn.end_line else fn.line
    return lo, hi


def bola_idor_candidates(
    graph: Graph,
    resource_categories: set = RESOURCE_SINK_CATEGORIES,
) -> List[Finding]:
    """Heuristic candidates for CWE-639 (BOLA/IDOR) and CWE-862 (missing auth).

    Flags a function when it (i) contains an HTTP-request source (a
    user-controlled object/resource selector), (ii) a resource-access sink, and
    (iii) is **not** behind any ``auth`` gate. Classic taint is blind here
    (the selector is often cast to ``int`` and thus *clean*); the structural
    signal is the *ungated* user-controlled resource access --- the path from a
    public entry point to a protected resource with no privilege boundary
    (``no_auth_bounded``) where one is required.

    This is a *structural heuristic* intended for a curated evaluation, not a
    production-grade detector: it deliberately ignores dataflow sanitization.
    """
    out: List[Finding] = []
    funcs = [n for n in graph.nodes if n.kind == NodeKind.FUNCTION]
    for fn in funcs:
        if fn.attrs.get("auth"):
            continue  # gated functions are handled by authorization_violations (crossing)
        lo, hi = _fn_span(fn)
        http_srcs = [n for n in graph.nodes if _is_http_source(n) and lo <= n.line <= hi]
        if not http_srcs:
            continue
        for sink in (n for n in graph.nodes
                     if n.kind == NodeKind.SINK and lo <= n.line <= hi
                     and n.attrs.get("category") in resource_categories):
            category = "idor" if sink.attrs.get("category") == "sql" else "missing_authorization"
            out.append(
                Finding(
                    kind="bola",
                    title=f"Possible BOLA/IDOR: ungated user-controlled resource access ({sink.label})",
                    description=(
                        f"HTTP input ({', '.join(s.label for s in http_srcs)}) reaches a "
                        f"{sink.attrs.get('category')} sink ({sink.label}) in '{fn.label}', which has "
                        "no authorization gate. A clean (cast) selector defeats taint analysis; "
                        "the structural signal is the missing privilege boundary."
                    ),
                    severity="high",
                    category=category,
                    file=sink.file,
                    line=sink.line,
                    source_names=[s.label for s in http_srcs],
                    sink_name=sink.label,
                )
            )
    return out
