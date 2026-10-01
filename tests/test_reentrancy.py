"""Tests for the Solidity adapter and reentrancy detection (hermetic fixtures)."""

import pytest

from valen.analysis.math_core import core_binary, topology
from valen.analysis.reentrancy import analyze, reentrancy_cycle_graph
from valen.ingest.solidity import SolidityIngest

VULNERABLE = '''pragma solidity ^0.4.19;
contract Bank {
  mapping(address => uint) balances;
  function collect(uint am) public payable {
    if (balances[msg.sender] >= am) {
      if (msg.sender.call.value(am)()) {
        balances[msg.sender] -= am;
      }
    }
  }
}'''

SAFE = '''pragma solidity ^0.4.19;
contract Bank {
  mapping(address => uint) balances;
  function withdraw(uint am) public payable {
    if (balances[msg.sender] >= am) {
      balances[msg.sender] -= am;
      msg.sender.transfer(am);
    }
  }
}'''

INTERNAL_ONLY = '''pragma solidity ^0.4.19;
contract A {
  uint x;
  function set(uint v) public { x = v; }
  function get() public view returns (uint) { return x; }
}'''


def test_solidity_ingest_builds_graph():
    graph = SolidityIngest().analyze(VULNERABLE).graph
    assert graph.meta["language"] == "solidity"
    functions = [n for n in graph.nodes if n.kind.value == "function"]
    assert any(n.label == "collect" for n in functions)


def test_reentrancy_detected_for_call_before_write():
    r = analyze(VULNERABLE)
    assert len(r["findings"]) == 1
    assert r["findings"][0].category == "reentrancy"


def test_reentrancy_not_detected_for_transfer_or_safe_order():
    assert analyze(SAFE)["findings"] == []
    assert analyze(INTERNAL_ONLY)["findings"] == []


def test_reentrancy_cycle_is_directed_2cycle(binary_available):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    graph = reentrancy_cycle_graph(SolidityIngest().analyze(VULNERABLE).graph)
    topo = topology(graph, "call")
    # directed 2-cycle f -> EXT -> f: GLMY sees it, symmetrization collapses it
    assert topo["directed_path"]["beta1"] >= 1
    assert topo["beta1"] == 0  # undirected collapses the 2-cycle


@pytest.fixture(scope="module")
def binary_available():
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False
