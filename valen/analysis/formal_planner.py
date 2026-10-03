"""Formal attack-plan *synthesis* (bounded model checking + cost minimization).

The boolean layer (``attack_paths.z3_escalation``) answers *is it reachable?*.
This module answers *what is the minimal-cost ordered sequence of actions?* — a
bounded model of the attack graph as a transition system:

* ``has(st, n)`` — principal ``n`` is compromised by step ``st``;
* each edge ``m -> n`` is an *action* ``taken_e`` that requires ``has(st, m)``
  and yields ``has(st+1, n)``;
* entries are compromised at step 0;
* ``z3.Optimize`` finds a model reaching the target while minimizing total
  action cost, and we reconstruct the ordered sequence.

This is the "exploit synthesis" upgrade over plain reachability: it produces the
narrative (technique-by-technique) and the cheapest route, not just a boolean.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

import z3

from ..ir import EdgeKind, Graph


def synthesize_plan(
    graph: Graph,
    sources: Sequence[str],
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
    max_steps: int = 8,
) -> List[Dict[str, Any]]:
    """Minimal-cost ordered action sequences to each reachable target.

    Returns ``[{target, cost, steps: [{from, to, relation, technique, cost}]}]``.
    """
    nodes = [n.id for n in graph.nodes]
    idx = {n: i for i, n in enumerate(nodes)}
    sources = {s for s in sources if s in idx}
    target_set = {t for t in targets if t in idx}
    if not sources or not target_set:
        return []

    edges = [(e.src, e.dst, e.attrs) for e in graph.edges(kind)
             if e.src in idx and e.dst in idx]
    if not edges:
        return []

    opt = z3.Optimize()
    taken = [z3.Bool(f"t{i}") for i in range(len(edges))]

    # cost as a Real objective
    cost = z3.RealVal(0)
    for i, (_, _, a) in enumerate(edges):
        try:
            c = float(a.get("cost", 1.0))
        except (TypeError, ValueError):
            c = 1.0
        cost = cost + z3.If(taken[i], z3.RealVal(c), z3.RealVal(0))

    has = [[z3.Bool(f"h{st}_{n}") for n in range(len(nodes))]
           for st in range(max_steps + 1)]
    for n, nid in enumerate(nodes):
        opt.add(has[0][n] == z3.BoolVal(nid in sources))
    for st in range(max_steps):
        for n, nid in enumerate(nodes):
            succ = has[st][n]
            for i, (m, d, _) in enumerate(edges):
                if d == nid:
                    succ = z3.Or(succ, z3.And(taken[i], has[st][idx[m]]))
            opt.add(has[st + 1][n] == succ)

    opt.minimize(cost)

    plans: List[Dict[str, Any]] = []
    labels = {n.id: n.label for n in graph.nodes}
    for target in sorted(target_set):
        reached = z3.Or([has[st][idx[target]] for st in range(max_steps + 1)])
        opt.push()
        opt.add(reached)
        res = opt.check()
        if res != z3.sat:
            opt.pop()
            continue
        model = opt.model()

        chosen = []
        for i, (m, d, a) in enumerate(edges):
            if z3.is_true(model.eval(taken[i], model_completion=True)):
                chosen.append((m, d, a, i))

        # order by earliest step the source becomes compromised
        def first_step(nid: str) -> int:
            for st in range(max_steps + 1):
                if z3.is_true(model.eval(has[st][idx[nid]], model_completion=True)):
                    return st
            return max_steps

        ordered = sorted(chosen, key=lambda e: (first_step(e[0]), float(e[2].get("cost", 1.0))))
        steps = [{
            "from": m, "to": d,
            "relation": a.get("ad_relation", a.get("relation", "")),
            "technique": a.get("technique", ""),
            "cost": float(a.get("cost", 1.0)),
        } for m, d, a, _ in ordered]

        total = sum(s["cost"] for s in steps)
        plans.append({
            "target": target,
            "cost": round(total, 3),
            "steps": steps,
            "path": [sources and next(iter(sources)), *[s["to"] for s in steps]],
            "labels": [labels.get(s["from"], s["from"]) for s in steps] + [labels.get(target, target)],
        })
        opt.pop()

    plans.sort(key=lambda p: p["cost"])
    return plans
