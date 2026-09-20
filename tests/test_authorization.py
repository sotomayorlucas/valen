"""Tests for the L4 operationalization (auth gates / naturality violations)."""

from pathlib import Path

from agent.agent import ManifoldAgent
from manifold.analysis.authorization import naturality_violations
from manifold.ingest.python import PythonIngest
from manifold.ir import EdgeKind, NodeKind

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


def test_auth_gate_edge_and_node_present():
    code = (EXAMPLES / "auth_bypass.py").read_text()
    graph = PythonIngest().analyze(code, path="auth_bypass.py").graph
    gates = [n for n in graph.nodes if n.kind == NodeKind.GATE]
    assert gates, "expected a GATE node for @login_required"
    assert any(n.label == "login_required" for n in gates)
    assert len(graph.edges(EdgeKind.AUTH)) >= 1


def test_naturality_violation_crosses_boundary():
    code = (EXAMPLES / "auth_bypass.py").read_text()
    result = PythonIngest().analyze(code, path="auth_bypass.py")
    assert len(result.findings) == 2

    violations = naturality_violations(result.graph, result.findings)
    assert len(violations) == 1
    assert violations[0].auth_gates == ["login_required"]


def test_agent_tags_auth_boundary_crossing():
    code = (EXAMPLES / "auth_bypass.py").read_text()
    report = ManifoldAgent().run(code, path="auth_bypass.py")
    sql = [e for e in report.confirmed if e.cwe == "CWE-89"]
    assert len(sql) == 2
    crossing = [e for e in sql if "auth boundary" in e.evidence]
    assert len(crossing) == 1
