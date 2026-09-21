"""angr-based binary adapter (the real symbolic-analysis backend).

Loads a binary with ``angr``, builds the interprocedural call graph with
``CFGFast``, and runs the same taint reachability (sources -> sinks) as the
lightweight objdump adapter --- but over angr's recovered control flow. Requires
``angr`` to be installed; the lightweight ``BinaryIngest`` remains the zero-
dependency fallback.
"""

from __future__ import annotations

from typing import Dict, List, Set

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind
from .binary import binary_category, is_binary_sink, is_binary_source, taint_closure


class AngrBinaryIngest:
    def analyze(self, binary_path: str, path: str | None = None) -> AnalysisResult:
        import angr  # noqa: F401  (lazy import)

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        cg = cfg.functions.callgraph

        graph = Graph()
        graph.meta = {
            "language": "binary",
            "file": path or binary_path,
            "backend": "angr",
        }

        node_by_name: Dict[str, str] = {}
        seq = 0

        def add_node(name: str, kind: NodeKind) -> str:
            nonlocal seq
            if name in node_by_name:
                return node_by_name[name]
            seq += 1
            nid = f"n{seq}"
            graph.add_node(nid, kind, name, file=path or binary_path)
            node_by_name[name] = nid
            return nid

        for fn in cfg.functions.values():
            if fn.is_simprocedure or fn.is_plt:
                continue
            add_node(fn.name, NodeKind.FUNCTION)

        # Call edges from the recovered interprocedural call graph.
        calls: List[tuple] = []  # (caller, callee)
        external: Set[str] = set()
        for u_addr, v_addr in cg.edges():
            u = cfg.functions.get(u_addr)
            v = cfg.functions.get(v_addr)
            if u is None or v is None:
                continue
            u_name = u.name
            v_name = v.name
            if u_name == "UnresolvableCallTarget" or v_name == "UnresolvableCallTarget":
                continue
            calls.append((u_name, v_name))
            if v.is_simprocedure or v.is_plt:
                external.add(v_name)

        for name in external:
            add_node(name, NodeKind.CALL)
        for caller, callee in calls:
            if caller in node_by_name and callee in node_by_name:
                graph.add_edge(node_by_name[caller], node_by_name[callee], EdgeKind.CALL)

        findings = self._findings(graph, calls, path or binary_path)
        return AnalysisResult(graph=graph, findings=findings)

    def _findings(self, graph: Graph, calls: List[tuple], path: str) -> List[Finding]:
        sources = {callee for _, callee in calls if is_binary_source(callee)}
        tainted = taint_closure([(c, k, 0) for c, k in calls], sources)

        findings: List[Finding] = []
        seq = 0
        for caller, callee in calls:
            if is_binary_sink(callee) and caller in tainted:
                seq += 1
                src_id = f"src_{seq}"
                graph.add_node(src_id, NodeKind.SOURCE, "input", file=path)
                sink_id = f"sink_{seq}"
                graph.add_node(
                    sink_id, NodeKind.SINK, callee, file=path,
                    attrs={"category": binary_category(callee)},
                )
                graph.add_edge(src_id, sink_id, EdgeKind.TAINT)
                findings.append(
                    Finding(
                        kind="taint",
                        title=f"Untrusted input reaches {callee}",
                        description=(
                            f"Function `{caller}` (transitively) receives input and "
                            f"calls dangerous `{callee}`."
                        ),
                        severity="high",
                        category=binary_category(callee),
                        file=path,
                        line=0,
                        source_names=["input"],
                        sink_name=callee,
                    )
                )
        return findings
