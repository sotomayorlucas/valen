"""State-space / protocol pivot: GLMY path homology on a directed state graph.

In a flat Java servlet there are no state cycles, so homology has nothing to
find. In a *state machine* (smart contracts, lock protocols, concurrency
controllers) the worst flaws are destructive feedback loops; there, a persistent
directed H1 generator is the exact signature of a reentrancy / deadlock cycle.
"""

import json
from pathlib import Path

import pytest

from valen.analysis.math_core import core_binary, topology
from valen.ir import Graph

EX = Path(__file__).resolve().parent.parent / "examples" / "state_machine"


@pytest.fixture(scope="module")
def binary_available() -> bool:
    try:
        core_binary()
        return True
    except FileNotFoundError:
        return False


def test_lock_cycle_glmy_directed_generator(binary_available):
    if not binary_available:
        pytest.skip("valen-core binary not built")
    data = json.loads((EX / "lock_cycle.json").read_text())
    graph = Graph.from_dict(data)
    topo = topology(graph, kind="call")
    dp = topo["directed_path"]
    # A pure directed cycle: GLMY path homology reports beta1 = 1 with the
    # concrete cycle as an H1 generator (directed edges, not a symmetrized one).
    assert dp["beta1"] == 1
    assert dp["h1_generators"], "expected a directed H1 generator"
    gen = dp["h1_generators"][0]
    assert len(gen) == 3  # the three directed edges of the cycle
