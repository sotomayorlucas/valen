"""LLM-agent adapter: turn an agent's tool/prompt description into a trust graph.

Input is a JSON spec describing the agent's tools and the entry point for
untrusted user input. Tools that can execute code, run shell commands or write
files are *sinks* (prompt-injection / tool-misuse); tools that require human
approval are guarded by a *gate* (auth edge, L4). A tool reachable by user input
without a gate is a finding.
"""

from __future__ import annotations

import json
from typing import Any, List

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind

_DANGEROUS = {"run_shell", "exec", "eval", "run_code", "write_file", "execute", "http_request"}


class LLMAgentIngest:
    def analyze(self, spec: Any, path: str = "<agent>") -> AnalysisResult:
        if isinstance(spec, str):
            spec = json.loads(spec)

        graph = Graph()
        graph.meta = {"language": "llm-agent", "file": path, "name": spec.get("name", "agent")}
        findings: List[Finding] = []
        seq = 0

        entry = spec.get("entry", "user_prompt")
        seq += 1
        user = f"src{seq}"
        graph.add_node(
            user, NodeKind.SOURCE, entry, file=path,
            attrs={"description": "untrusted user prompt"},
        )

        for tool in spec.get("tools") or []:
            seq += 1
            name = tool.get("name", "tool")
            tid = f"tool{seq}"
            dangerous = name in _DANGEROUS or tool.get("dangerous", False)
            graph.add_node(
                tid, NodeKind.FUNCTION, name, file=path,
                attrs={"dangerous": dangerous, "description": tool.get("description", "")},
            )
            graph.add_edge(user, tid, EdgeKind.DATA)

            if tool.get("requires_approval"):
                seq += 1
                gate = f"gate{seq}"
                graph.add_node(gate, NodeKind.GATE, "human_approval", file=path)
                graph.add_edge(gate, tid, EdgeKind.AUTH)

            if dangerous:
                seq += 1
                sink = f"sink{seq}"
                graph.add_node(sink, NodeKind.SINK, name, file=path, attrs={"category": "tool_misuse"})
                graph.add_edge(tid, sink, EdgeKind.TAINT)
                if not tool.get("requires_approval"):
                    findings.append(
                        Finding(
                            kind="taint",
                            title=f"User prompt reaches dangerous tool `{name}`",
                            description=(
                                f"Tool `{name}` is reachable from untrusted user "
                                f"input without a human-approval gate (prompt "
                                f"injection / tool misuse)."
                            ),
                            severity="critical" if name in ("run_shell", "exec", "eval", "run_code") else "high",
                            category="tool_misuse",
                            file=path,
                            line=0,
                            source_names=[entry],
                            sink_name=name,
                        )
                    )

        return AnalysisResult(graph=graph, findings=findings)
