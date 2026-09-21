"""Tests for the IR data model."""

from valen.ir import EdgeKind, Graph, NodeKind


def test_add_and_lookup():
    g = Graph()
    g.add_node("a", NodeKind.FUNCTION, "foo")
    g.add_node("b", NodeKind.CALL, "bar")
    g.add_edge("a", "b", EdgeKind.CALL)
    assert g.node_count == 2
    assert g.edge_count == 1
    assert g.node("a").label == "foo"
    assert g.neighbors("a", EdgeKind.CALL) == ["b"]


def test_edge_kind_counts():
    g = Graph()
    g.add_node("a", NodeKind.FUNCTION, "foo")
    g.add_node("b", NodeKind.CALL, "bar")
    g.add_node("c", NodeKind.CALL, "baz")
    g.add_edge("a", "b", EdgeKind.CALL)
    g.add_edge("a", "c", EdgeKind.CALL)
    g.add_edge("b", "c", EdgeKind.DATA)
    assert g.edge_kind_counts() == {"call": 2, "data": 1}


def test_json_roundtrip():
    g = Graph()
    g.meta = {"language": "python"}
    g.add_node("a", NodeKind.SOURCE, "input", line=1)
    g.add_node("b", NodeKind.SINK, "eval", line=2)
    g.add_edge("a", "b", EdgeKind.TAINT, attrs={"category": "code_execution"})
    g2 = Graph.from_dict(g.to_dict())
    assert g2.node_count == 2
    assert g2.edge_count == 1
    assert g2.node("a").kind == NodeKind.SOURCE
    assert g2.edges(EdgeKind.TAINT)[0].attrs["category"] == "code_execution"
