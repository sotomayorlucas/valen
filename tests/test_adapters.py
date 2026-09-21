"""Tests for the multi-domain adapters (F7): binary, web, LLM agent, angr."""

import shutil
import subprocess
from pathlib import Path

import pytest

from valen.ingest import analyze, infer_adapter
from valen.ingest.binary import BinaryIngest
from valen.ingest.llm_agent import LLMAgentIngest
from valen.ingest.web import WebIngest
from valen.ir import EdgeKind, NodeKind

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_binary_detects_command_flow():
    code = (EXAMPLES / "binary" / "vuln.asm").read_text()
    result = BinaryIngest().analyze(code, path="vuln.asm")
    # Only main (scanf -> system) is flagged; helper and safe are not.
    assert len(result.findings) == 1
    assert result.findings[0].sink_name == "system"
    assert result.findings[0].category == "command_execution"


def test_web_emits_gate_and_sinks():
    spec = (EXAMPLES / "web" / "api.json").read_text()
    result = WebIngest().analyze(spec, path="api.json")
    # /users/search (taint + missing auth) and /admin/users (taint, gated).
    assert len(result.findings) == 3
    gates = [n for n in result.graph.nodes if n.kind == NodeKind.GATE]
    assert any(n.label == "apiKey" for n in gates)
    assert len(result.graph.edges(EdgeKind.AUTH)) >= 1


def test_web_missing_authorization_cwe862():
    spec = (EXAMPLES / "web" / "api.json").read_text()
    result = WebIngest().analyze(spec, path="api.json")
    missing = [f for f in result.findings if f.kind == "missing_authorization"]
    assert len(missing) == 1
    # only the operation with a declared sink but NO security scheme is flagged
    assert "searchUsers" in missing[0].title
    assert missing[0].category == "missing_authorization"


def test_llm_agent_gates_dangerous_tool():
    spec = (EXAMPLES / "llm_agent" / "agent.json").read_text()
    result = LLMAgentIngest().analyze(spec, path="agent.json")
    sinks = {f.sink_name for f in result.findings}
    # write_file and run_code are ungated and flagged; run_shell is gated.
    assert "write_file" in sinks
    assert "run_code" in sinks
    assert "run_shell" not in sinks
    gates = [n for n in result.graph.nodes if n.kind == NodeKind.GATE]
    assert any(n.label == "human_approval" for n in gates)


def test_dispatch_and_inference():
    # JSON with "tools" -> llm-agent; JSON with "paths" -> web.
    assert infer_adapter('{"tools": []}', "x.json") == "llm-agent"
    assert infer_adapter('{"paths": {}}', "x.json") == "web"
    assert infer_adapter("...", "x.asm") == "binary"

    spec = (EXAMPLES / "web" / "api.json").read_text()
    result = analyze(spec, path="api.json")
    assert result.graph.meta["language"] == "openapi"


def _have_angr():
    try:
        import angr  # noqa: F401

        return shutil.which("gcc") is not None
    except ImportError:
        return False


@pytest.mark.skipif(not _have_angr(), reason="angr or gcc not available")
def test_angr_binary_detects_command_flow(tmp_path):
    from valen.ingest.angr_binary import AngrBinaryIngest

    src = tmp_path / "vuln.c"
    src.write_text(
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "int main(void){char b[64];scanf(\"%63s\",b);system(b);return 0;}\n"
    )
    bin_path = tmp_path / "vuln"
    subprocess.run(["gcc", "-o", str(bin_path), str(src)], check=True)

    result = AngrBinaryIngest().analyze(str(bin_path), path="vuln")
    sinks = {f.sink_name for f in result.findings}
    assert "system" in sinks

