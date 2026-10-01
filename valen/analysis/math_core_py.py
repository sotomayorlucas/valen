"""Pure-Python fallback for the Rust numeric core (``valen-core``).

Used when the compiled binary is unavailable (e.g. ``pip install valen`` without
a Rust toolchain). It produces the *same JSON schema* as ``core/src/main.rs`` so
the UI/CLI/report layers are agnostic to which engine ran:

    {node_order, spectral{call,data,control}, geometry{...}, topology{...},
     centrality{...}}

It is an honest approximation, not a drop-in for the Rust kernels: persistent
homology is reduced to Betti numbers + a fundamental-cycle basis, GLMY path
homology to a directed cycle-rank estimate, and the Ollivier-Ricci curvature to
the closed-form Forman curvature. Set ``VALEN_CORE_BIN`` to use the real core.
"""

from __future__ import annotations

import math
import random
from typing import Any, Dict, List, Sequence, Set, Tuple

_KINDS = ("call", "data", "control")


def _index(nodes: Sequence[Dict[str, Any]]) -> Tuple[List[str], Dict[str, int]]:
    ids = [n["id"] for n in nodes]
    return ids, {nid: i for i, nid in enumerate(ids)}


def _adjacency(edges, idx, kinds, undirected=True):
    """Out-adjacency list-of-sets for edges whose kind is in ``kinds``."""
    n = len(idx)
    adj: List[Set[int]] = [set() for _ in range(n)]
    for e in edges:
        if e.get("kind") not in kinds:
            continue
        a = idx.get(e.get("src"))
        b = idx.get(e.get("dst"))
        if a is None or b is None or a == b:
            continue
        adj[a].add(b)
        if undirected:
            adj[b].add(a)
    return adj


# ---------------------------------------------------------------------------
# spectral
# ---------------------------------------------------------------------------
def _smallest_positive_fiedler(adj: List[Set[int]]) -> Tuple[float, List[int], List[float]]:
    """Return (lambda2, component_nodes, local_fiedler_vector) for the connected
    component whose smallest nonzero Laplacian eigenvalue is the global minimum.

    This mirrors the Rust core, which skips the zero eigenvalues contributed by
    isolated nodes and returns the first strictly-positive one.
    """
    best: Tuple[float, List[int], List[float]] | None = None
    for comp in _components(adj):
        m = len(comp)
        if m < 2:
            continue
        cset = set(comp)
        loc = {g: i for i, g in enumerate(comp)}
        localdeg = [sum(1 for w in adj[g] if w in cset) for g in comp]
        if max(localdeg) == 0:
            continue
        rnd = random.Random(0)
        v = [rnd.random() - 0.5 for _ in range(m)]
        mean = sum(v) / m
        v = [x - mean for x in v]
        nrm = math.sqrt(sum(x * x for x in v)) or 1.0
        v = [x / nrm for x in v]
        eps = 0.5 / max(1, max(localdeg))
        for _ in range(300):
            w = []
            for i, g in enumerate(comp):
                s = sum(v[loc[w2]] for w2 in adj[g] if w2 in cset)
                w.append(v[i] - eps * (localdeg[i] * v[i] - s))
            mean = sum(w) / m
            w = [x - mean for x in w]
            nrm = math.sqrt(sum(x * x for x in w)) or 1.0
            v = [x / nrm for x in w]
        lv = [
            localdeg[i] * v[i]
            - sum(v[loc[w2]] for w2 in adj[comp[i]] if w2 in cset)
            for i in range(m)
        ]
        lam = sum(v[i] * lv[i] for i in range(m)) / (sum(x * x for x in v) or 1.0)
        lam = max(0.0, lam)
        if best is None or lam < best[0]:
            best = (lam, comp, v)
    if best is None:
        return 0.0, [], []
    return best


def _fiedler(adj: List[Set[int]]) -> Tuple[List[int], float, List[float]]:
    n = len(adj)
    deg = [len(a) for a in adj]
    if n == 0:
        return [], 0.0, []
    if n == 1:
        return [0], 0.0, [0.0]
    lam, comp, v = _smallest_positive_fiedler(adj)
    out = [0.0] * n
    for i, g in enumerate(comp):
        out[g] = v[i]
    return deg, lam, out


def _spectral_block(nodes, edges, idx) -> Dict[str, Any]:
    adj = _adjacency(edges, idx, {"call"}, undirected=True)
    _, lam, vec = _fiedler(adj)
    # directed: SCC count as a coarse "scc_size"; reuse the undirected spectrum
    scc = _sccs(_adjacency(edges, idx, {"call"}, undirected=False), len(idx))
    d_scc = max((len(c) for c in scc), default=0)
    return {
        "lambda2": lam,
        "fiedler": vec,
        "embedding": {"eigenvalues": [lam], "eigenvectors": [vec]},
        "directed": {"scc_size": d_scc, "lambda2": lam, "fiedler": vec},
    }


# ---------------------------------------------------------------------------
# geometry
# ---------------------------------------------------------------------------
def _forman(adj: List[Set[int]]) -> List[Dict[str, Any]]:
    out = []
    for u in range(len(adj)):
        for v in sorted(adj[u]):
            if u < v:
                out.append({"src": u, "dst": v, "kappa": float(4 - len(adj[u]) - len(adj[v]))})
    return out


def _geometry_block(nodes, edges, idx) -> Dict[str, Any]:
    adj = _adjacency(edges, idx, {"call"}, undirected=True)
    forman = _forman(adj)
    # Ollivier-Ricci approximated by Forman in the fallback (documented).
    return {
        "ollivier_ricci": [dict(e) for e in forman],
        "ollivier_ricci_sinkhorn": [dict(e) for e in forman],
        "forman_ricci": forman,
    }


# ---------------------------------------------------------------------------
# topology
# ---------------------------------------------------------------------------
def _sccs(adj: List[Set[int]], n: int) -> List[List[int]]:
    index = [-1] * n
    low = [0] * n
    on = [False] * n
    stack: List[int] = []
    counter = [0]
    out: List[List[int]] = []

    def strong(v: int) -> None:
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on[v] = True
        for w in adj[v]:
            if index[w] == -1:
                strong(w)
                low[v] = min(low[v], low[w])
            elif on[w]:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on[w] = False
                comp.append(w)
                if w == v:
                    break
            out.append(comp)

    import sys
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old, n + 100))
    try:
        for v in range(n):
            if index[v] == -1:
                strong(v)
    finally:
        sys.setrecursionlimit(old)
    return out


def _components(adj: List[Set[int]]) -> List[List[int]]:
    n = len(adj)
    seen = [False] * n
    comps = []
    for s in range(n):
        if seen[s]:
            continue
        stack = [s]
        seen[s] = True
        comp = []
        while stack:
            v = stack.pop()
            comp.append(v)
            for w in adj[v]:
                if not seen[w]:
                    seen[w] = True
                    stack.append(w)
        comps.append(comp)
    return comps


def _cycle_basis(adj: List[Set[int]]) -> List[List[int]]:
    """A fundamental cycle basis via a BFS spanning forest."""
    n = len(adj)
    parent = [-1] * n
    depth = [-1] * n
    tree_edges: Set[Tuple[int, int]] = set()
    for s in range(n):
        if depth[s] != -1:
            continue
        depth[s] = 0
        queue = [s]
        while queue:
            v = queue.pop(0)
            for w in adj[v]:
                if depth[w] == -1:
                    depth[w] = depth[v] + 1
                    parent[w] = v
                    tree_edges.add((min(v, w), max(v, w)))
                    queue.append(w)
    cycles: List[List[int]] = []
    for u in range(n):
        for v in sorted(adj[u]):
            if u < v and (u, v) not in tree_edges:
                a, b = u, v
                path_a, path_b = [a], [b]
                while depth[a] > depth[b]:
                    a = parent[a]
                    path_a.append(a)
                while depth[b] > depth[a]:
                    b = parent[b]
                    path_b.append(b)
                while a != b:
                    a = parent[a]
                    b = parent[b]
                    path_a.append(a)
                    path_b.append(b)
                # path_a: u -> LCA ; path_b: v -> LCA ; drop the duplicated LCA
                cycles.append(path_a + list(reversed(path_b[:-1])))
    return cycles


def _topology_block(nodes, edges, idx) -> Dict[str, Any]:
    adj = _adjacency(edges, idx, {"call"}, undirected=True)
    m_edges = sum(len(a) for a in adj) // 2
    n = len(adj)
    comps = _components(adj)
    beta0 = len(comps)
    beta1 = max(0, m_edges - n + beta0)
    cycles = _cycle_basis(adj)

    dadj = _adjacency(edges, idx, {"call"}, undirected=False)
    sccs = _sccs(dadj, n)
    dp_beta1 = 0
    for comp in sccs:
        c = set(comp)
        ce = sum(1 for u in comp for w in dadj[u] if w in c)
        if len(c) > 1:
            dp_beta1 += max(0, ce - len(c) + 1)

    h1 = [
        {"birth": 0.0,
         "nodes": [nodes[i]["id"] for i in c]}
        for c in cycles
    ]
    return {
        "beta0": beta0,
        "beta1": beta1,
        "h0_bars": [{"birth": 0.0, "death": float("inf")}] * beta0,
        "h1_cycles": h1,
        "mapper": {"clusters": [], "nerve": {}},
        "directed_path": {
            "beta0": len(comps),
            "beta1": dp_beta1,
            "vertices": n,
            "edges": sum(len(a) for a in dadj),
            "paths2": 0,
            "h1_generators": [],
        },
    }


# ---------------------------------------------------------------------------
# centrality
# ---------------------------------------------------------------------------
def _betweenness(adj: List[Set[int]], n: int) -> List[float]:
    cb = [0.0] * n
    for s in range(n):
        stack: List[int] = []
        pred: List[List[int]] = [[] for _ in range(n)]
        sigma = [0.0] * n
        dist = [-1] * n
        sigma[s] = 1.0
        dist[s] = 0
        queue = [s]
        while queue:
            v = queue.pop(0)
            stack.append(v)
            for w in adj[v]:
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        delta = [0.0] * n
        while stack:
            w = stack.pop()
            for v in pred[w]:
                if sigma[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]
    return cb


def _pagerank(adj: List[Set[int]], n: int, iters: int = 20, damping: float = 0.85) -> List[float]:
    if n == 0:
        return []
    pr = [1.0 / n] * n
    outdeg = [len(a) for a in adj]
    for _ in range(iters):
        new = [(1.0 - damping) / n] * n
        for i in range(n):
            if outdeg[i] == 0:
                share = damping * pr[i] / n
                for j in range(n):
                    new[j] += share
            else:
                share = damping * pr[i] / outdeg[i]
                for j in adj[i]:
                    new[j] += share
        pr = new
    return pr


def _centrality_block(nodes, edges, idx) -> Dict[str, Any]:
    adj = _adjacency(edges, idx, {"call"}, undirected=False)
    ids = [n["id"] for n in nodes]
    bt = _betweenness(adj, len(ids))
    pr = _pagerank(adj, len(ids))
    return {
        "betweenness": [[ids[i], bt[i]] for i in range(len(ids))],
        "pagerank": [[ids[i], pr[i]] for i in range(len(ids))],
    }


# ---------------------------------------------------------------------------
def run_core_python(graph_dict: Dict[str, Any]) -> Dict[str, Any]:
    nodes = graph_dict.get("nodes", [])
    edges = graph_dict.get("edges", [])
    ids, idx = _index(nodes)
    return {
        "engine": "python-fallback",
        "node_order": ids,
        "spectral": {k: _spectral_block(nodes, edges, idx) for k in _KINDS},
        "geometry": {k: _geometry_block(nodes, edges, idx) for k in _KINDS},
        "topology": {k: _topology_block(nodes, edges, idx) for k in _KINDS},
        "centrality": {k: _centrality_block(nodes, edges, idx) for k in _KINDS},
    }
