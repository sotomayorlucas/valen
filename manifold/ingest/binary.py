"""Binary adapter: turn an `objdump -d` disassembly into the IR.

Parses function labels and `call` instructions into a call graph, then runs an
interprocedural taint reachability: input routines (`scanf`, `read`, `recv`, ...)
are taint *sources*, dangerous calls (`system`, `execve`, `strcpy`, `sprintf`,
`gets`, ...) are *sinks*. A function is vulnerable if it (transitively) receives
input and calls a sink. This is the "taint as an automaton" reachability (L6)
without needing a full symbolic engine such as angr.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from ..analysis import AnalysisResult, Finding
from ..ir import EdgeKind, Graph, NodeKind

_FUNC_RE = re.compile(r"^[0-9a-f]+\s+<([^>]+)>:$")
_CALL_RE = re.compile(r"\bcall\b\s+[0-9a-f]+\s+<([^>]+)>")

# Imported names are typically suffixed with `@plt` / `@got`.
_SOURCES = {
    "scanf", "__isoc99_scanf", "fscanf", "gets", "fgets", "read", "recv",
    "recvfrom", "fread", "getchar", "getenv",
}
_SINKS = {
    "system", "execve", "execv", "execvp", "execl", "execlp", "popen",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "mktemp",
}


def _strip_plt(name: str) -> str:
    return name.split("@", 1)[0]


class BinaryIngest:
    def analyze(self, disassembly: str, path: str = "<binary>") -> AnalysisResult:
        graph = Graph()
        graph.meta = {"language": "asm", "file": path}

        functions: Dict[str, str] = {}  # name -> node id
        calls: List[tuple] = []  # (caller_name, callee_name, line)
        current: str | None = None

        for lineno, line in enumerate(disassembly.splitlines(), start=1):
            m = _FUNC_RE.match(line)
            if m:
                current = _strip_plt(m.group(1))
                if current not in functions:
                    fid = f"fn{len(functions) + 1}"
                    functions[current] = fid
                    graph.add_node(
                        fid, NodeKind.FUNCTION, current, file=path, line=lineno
                    )
                continue
            cm = _CALL_RE.search(line)
            if cm and current is not None:
                calls.append((current, _strip_plt(cm.group(1)), lineno))

        # Call edges (only among defined functions + external symbols as nodes).
        for caller, callee, lineno in calls:
            if callee not in functions:
                # Create a node for the external symbol (import).
                functions[callee] = f"ext{len(functions) + 1}"
                graph.add_node(
                    functions[callee], NodeKind.CALL, callee, file=path, line=lineno
                )
            graph.add_edge(functions[caller], functions[callee], EdgeKind.CALL)

        findings = self._taint_findings(graph, functions, calls, path)
        return AnalysisResult(graph=graph, findings=findings)

    def _taint_findings(self, graph, functions, calls, path) -> List[Finding]:
        # Directly tainted: functions that call an input routine.
        tainted: Set[str] = {c for c, callee, _ in calls if callee in _SOURCES}

        # Transitive closure over the call graph (function -> called functions).
        call_map: Dict[str, Set[str]] = {}
        for caller, callee, _ in calls:
            call_map.setdefault(caller, set()).add(callee)

        changed = True
        while changed:
            changed = False
            for caller, callees in call_map.items():
                if caller in tainted:
                    continue
                if callees & tainted:
                    tainted.add(caller)
                    changed = True

        findings: List[Finding] = []
        seq = 0
        for caller, callee, lineno in calls:
            if callee in _SINKS and caller in tainted:
                # Source node + sink node + taint edge for the map.
                seq += 1
                src_id = f"src_{seq}"
                graph.add_node(src_id, NodeKind.SOURCE, "input", file=path, line=lineno)
                sink_id = f"sink_{seq}"
                graph.add_node(
                    sink_id, NodeKind.SINK, callee, file=path, line=lineno,
                    attrs={"category": self._category(callee)},
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
                        category=self._category(callee),
                        file=path,
                        line=lineno,
                        source_names=["input"],
                        sink_name=callee,
                    )
                )
        return findings

    def _category(self, sink: str) -> str:
        if sink in ("system", "execve", "execv", "execvp", "execl", "execlp", "popen"):
            return "command_execution"
        if sink in ("strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy"):
            return "memory_corruption"
        return "dangerous_call"
