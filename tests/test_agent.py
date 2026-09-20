"""Tests for the autonomous agent (offline, no LLM required)."""

from pathlib import Path

import pytest

from agent.agent import ManifoldAgent
from agent.llm import LLMClient
from manifold.analysis.math_core import core_binary

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "python"


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def _run(name: str):
    code = (EXAMPLES / name).read_text()
    agent = ManifoldAgent(llm=LLMClient(model="__offline__"))
    return agent.run(code, path=name)


def test_agent_confirms_sqli():
    report = _run("sqli.py")
    sql = [e for e in report.confirmed if e.cwe == "CWE-89"]
    assert sql, f"expected a confirmed SQL injection, got {report.to_dict()}"
    assert sql[0].line == 9


def test_agent_reports_nothing_on_safe():
    report = _run("safe.py")
    assert report.confirmed == []


def test_agent_confirms_sanitized_only_vulnerable():
    report = _run("sanitized.py")
    assert len(report.confirmed) == 1
    assert report.confirmed[0].line == 9


def test_agent_detects_reentrancy_cycle(binary_available):
    if not binary_available:
        pytest.skip("manifold-core binary not built")
    report = _run("reentrancy.py")
    cycles = [e for e in report.confirmed if e.cwe == "CWE-835"]
    assert cycles, f"expected a cycle finding, got {report.to_dict()}"
    assert "withdraw" in cycles[0].region or "read_balance" in cycles[0].region


def test_report_serializes():
    report = _run("sqli.py")
    data = report.to_dict()
    assert "entries" in data
    assert data["entries"]


def test_llm_client_offline_is_unavailable_or_returns_none():
    client = LLMClient(model="__offline__")
    # Without LiteLLM installed/configured, complete() must never raise.
    result = client.complete([{"role": "user", "content": "hi"}])
    assert result is None or isinstance(result, str)
