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

from typing import Any, Dict, List, Optional, Sequence

import z3

from ..ir import EdgeKind, Graph


def synthesize_plan(
    graph: Graph,
    sources: Sequence[str],
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
    max_steps: int = 8,
    compound_actions: Optional[Sequence[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Minimal-cost ordered action sequences to each reachable target.

    ``compound_actions`` are AND-precondition actions: each is ``{sources: [...],
    target, relation, technique, cost}`` and only fires when *all* sources are
    compromised (e.g. "DCSync requires Domain Admins AND a session on a DC").

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
    compounds = []
    for c in compound_actions or []:
        srcs = [s for s in (c.get("sources") or []) if s in idx]
        tgt = c.get("target", "")
        if srcs and tgt in idx:
            compounds.append({"sources": srcs, "target": tgt,
                              "relation": c.get("relation", "AND"),
                              "technique": c.get("technique", ""),
                              "cost": float(c.get("cost", 1.0))})
    if not edges and not compounds:
        return []

    opt = z3.Optimize()
    n_edges = len(edges)
    taken = [z3.Bool(f"t{i}") for i in range(n_edges + len(compounds))]

    def action_cost(i: int) -> float:
        if i < n_edges:
            a = edges[i][2]
        else:
            a = compounds[i - n_edges]
        try:
            return float(a.get("cost", 1.0))
        except (TypeError, ValueError):
            return 1.0

    cost = z3.RealVal(0)
    for i in range(len(taken)):
        cost = cost + z3.If(taken[i], z3.RealVal(action_cost(i)), z3.RealVal(0))

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
            for j, c in enumerate(compounds):
                if c["target"] == nid:
                    pre = z3.And([has[st][idx[s]] for s in c["sources"]])
                    succ = z3.Or(succ, z3.And(taken[n_edges + j], pre))
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
        for j, c in enumerate(compounds):
            if z3.is_true(model.eval(taken[n_edges + j], model_completion=True)):
                chosen.append(("&".join(c["sources"]), c["target"], c, n_edges + j))

        def first_step(nid: str) -> int:
            for st in range(max_steps + 1):
                if z3.is_true(model.eval(has[st][idx[nid]], model_completion=True)):
                    return st
            return max_steps

        def src_steps(from_field: str) -> int:
            return max(first_step(s) for s in from_field.split("&"))

        ordered = sorted(chosen, key=lambda e: (src_steps(e[0]), action_cost(e[3])))
        steps = [{
            "from": m, "to": d,
            "relation": a.get("ad_relation", a.get("relation", "")),
            "technique": a.get("technique", ""),
            "cost": float(a.get("cost", 1.0)),
        } for m, d, a, _ in ordered]

        total = sum(s["cost"] for s in steps)
        entry = next(iter(sources))
        plans.append({
            "target": target,
            "cost": round(total, 3),
            "steps": steps,
            "path": [entry, *[s["to"] for s in steps]],
            "labels": [labels.get(s["from"].split("&")[0], s["from"].split("&")[0]) for s in steps]
                      + [labels.get(target, target)],
        })
        opt.pop()

    plans.sort(key=lambda p: p["cost"])
    return plans
