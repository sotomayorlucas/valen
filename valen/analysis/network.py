"""Advanced network algorithms over the attack graph.

The base layer (spectral / topological / geometric / algebraic) describes
*structure*. This layer adds the *flow, path and probabilistic* machinery a red
teamer actually plans with:

* ``hitting_probabilities`` — absorbing Markov chain: probability that a random
  walk reaches a target set, from every node (a probabilistic risk ranking).
* ``eigenvector_centrality`` / ``katz_centrality`` / ``hits`` — spectral
  centralities (influence, hubs/authorities) for targeting and pivoting.
* ``weighted_shortest_paths`` — Dijkstra over a per-edge cost model (stealth +
  effort), the least-cost attack plan rather than the fewest-hop one.
* ``min_vertex_cut`` — Menger/min-cut: the minimum set of vertices whose removal
  disconnects the entry set from the target set (the *obligatory chokepoints*).

All operate on the generic typed IR, so they work for AD, IAM, network topology
or any other ``Graph``.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..ir import EdgeKind, Graph


def out_neighbors(graph: Graph, kind: EdgeKind = EdgeKind.CALL) -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = {n.id: [] for n in graph.nodes}
    for e in graph.edges(kind):
        if e.src in adj and e.dst in adj:
            adj[e.src].append(e.dst)
    return adj


def edge_costs(graph: Graph, kind: EdgeKind = EdgeKind.CALL) -> Dict[Tuple[str, str], float]:
    """Per-edge cost, read from ``attrs['cost']`` (default 1.0)."""
    out: Dict[Tuple[str, str], float] = {}
    for e in graph.edges(kind):
        try:
            c = float(e.attrs.get("cost", 1.0))
        except (TypeError, ValueError):
            c = 1.0
        out[(e.src, e.dst)] = max(c, 0.0)
    return out


# ---------------------------------------------------------------------------
# Probabilistic reachability (absorbing Markov chain)
# ---------------------------------------------------------------------------
def hitting_probabilities(
    graph: Graph,
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
    tol: float = 1e-9,
    max_iter: int = 100_000,
) -> Dict[str, float]:
    """Probability of ever reaching ``targets`` under a uniform random walk.

    Equivalent to the harmonic measure of the target set in the directed graph;
    computed by value iteration (fixed point of ``h(u) = mean(h(v))`` over
    out-neighbours, with ``h(target) = 1``). Unreachable-or-dead-end nodes keep
    probability 0.
    """
    targets = set(targets)
    adj = out_neighbors(graph, kind)
    nodes = list(adj)
    idx = {n: i for i, n in enumerate(nodes)}
    h = [1.0 if n in targets else 0.0 for n in nodes]
    for _ in range(max_iter):
        delta = 0.0
        for i, n in enumerate(nodes):
            if n in targets:
                continue
            nbrs = adj[n]
            val = sum(h[idx[m]] for m in nbrs) / len(nbrs) if nbrs else 0.0
            delta = max(delta, abs(val - h[i]))
            h[i] = val
        if delta < tol:
            break
    return {n: round(h[i], 6) for i, n in enumerate(nodes)}


# ---------------------------------------------------------------------------
# Exact hitting probability via (I - Q)^{-1} R (Gaussian elimination)
# ---------------------------------------------------------------------------
def hitting_probabilities_exact(
    graph: Graph,
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
) -> Dict[str, float]:
    """Hitting probability to ``targets`` by solving the absorbing chain exactly.

    For transient nodes, ``h = Q h + r`` where ``Q`` is the transient-to-transient
    transition and ``r_i`` is the mass to absorbing targets in one step; solve
    ``(I - Q) h = r`` by Gaussian elimination. O(n^3), exact — for when the value
    iteration is not enough (large or ill-conditioned graphs).
    """
    targets = set(targets)
    adj = out_neighbors(graph, kind)
    nodes = list(adj)
    transient = [n for n in nodes if n not in targets]
    n = len(transient)
    if n == 0:
        return {node: (1.0 if node in targets else 0.0) for node in nodes}

    ti = {node: i for i, node in enumerate(transient)}
    # build A = I - Q (n x n) and b = r (n x 1)
    A = [[0.0] * n for _ in range(n)]
    b = [0.0] * n
    for i, node in enumerate(transient):
        A[i][i] = 1.0
        nbrs = adj[node]
        if not nbrs:
            b[i] = 0.0
            continue
        p = 1.0 / len(nbrs)
        for m in nbrs:
            if m in targets:
                b[i] += p
            else:
                A[i][ti[m]] -= p

    # Gaussian elimination with partial pivoting
    for col in range(n):
        pivot = max(range(col, n), key=lambda r: abs(A[r][col]))
        if abs(A[pivot][col]) < 1e-15:
            continue
        A[col], A[pivot] = A[pivot], A[col]
        b[col], b[pivot] = b[pivot], b[col]
        for r in range(col + 1, n):
            f = A[r][col] / A[col][col]
            for c in range(col, n):
                A[r][c] -= f * A[col][c]
            b[r] -= f * b[col]
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        s = b[i] - sum(A[i][j] * x[j] for j in range(i + 1, n))
        x[i] = s / A[i][i] if abs(A[i][i]) > 1e-15 else 0.0

    result = {node: 1.0 for node in targets}
    for i, node in enumerate(transient):
        result[node] = round(max(0.0, min(1.0, x[i])), 9)
    for node in nodes:
        if node not in result:
            result[node] = 0.0
    return result


# ---------------------------------------------------------------------------
# Articulation points and bridges (Tarjan) — optimal-defense-disruption
# ---------------------------------------------------------------------------
def _undirected(graph: Graph, kind: EdgeKind) -> Dict[str, List[str]]:
    adj: Dict[str, List[str]] = {n.id: [] for n in graph.nodes}
    seen = set()
    for e in graph.edges(kind):
        if e.src in adj and e.dst in adj:
            key = tuple(sorted((e.src, e.dst)))
            if key not in seen:
                seen.add(key)
                adj[e.src].append(e.dst)
                adj[e.dst].append(e.src)
    return adj


def articulation_points(graph: Graph, kind: EdgeKind = EdgeKind.CALL) -> List[str]:
    """Cut vertices: whose removal disconnects the graph (Tarjan, undirected)."""
    adj = _undirected(graph, kind)
    nodes = list(adj)
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    visited: set = set()
    ap: set = set()
    time = 0

    def dfs(u: str) -> None:
        nonlocal time
        visited.add(u)
        disc[u] = low[u] = time
        time += 1
        children = 0
        for v in adj[u]:
            if v not in visited:
                parent[v] = u
                children += 1
                dfs(v)
                low[u] = min(low[u], low[v])
                if parent.get(u) is None and children > 1:
                    ap.add(u)
                if parent.get(u) is not None and low[v] >= disc[u]:
                    ap.add(u)
            elif v != parent.get(u):
                low[u] = min(low[u], disc[v])

    for n in nodes:
        if n not in visited:
            parent[n] = None
            dfs(n)
    return sorted(ap)


def bridges(graph: Graph, kind: EdgeKind = EdgeKind.CALL) -> List[Tuple[str, str]]:
    """Bridge edges: whose removal disconnects the graph (Tarjan)."""
    adj = _undirected(graph, kind)
    nodes = list(adj)
    disc: Dict[str, int] = {}
    low: Dict[str, int] = {}
    parent: Dict[str, Optional[str]] = {}
    visited: set = set()
    result: List[Tuple[str, str]] = []
    time = 0

    def dfs(u: str) -> None:
        nonlocal time
        visited.add(u)
        disc[u] = low[u] = time
        time += 1
        for v in adj[u]:
            if v not in visited:
                parent[v] = u
                dfs(v)
                low[u] = min(low[u], low[v])
                if low[v] > disc[u]:
                    result.append((u, v))
            elif v != parent.get(u):
                low[u] = min(low[u], disc[v])

    for n in nodes:
        if n not in visited:
            parent[n] = None
            dfs(n)
    return result


def vertex_connectivity(graph: Graph, sources: Sequence[str], targets: Sequence[str],
                        kind: EdgeKind = EdgeKind.CALL) -> int:
    """Minimum number of internal vertices separating sources from targets."""
    value, _ = min_vertex_cut(graph, sources, targets, kind)
    return value


# ---------------------------------------------------------------------------
# Spectral centralities (pure-Python power iteration)
# ---------------------------------------------------------------------------
def eigenvector_centrality(
    graph: Graph,
    kind: EdgeKind = EdgeKind.CALL,
    tol: float = 1e-9,
    max_iter: int = 1000,
) -> Dict[str, float]:
    adj = out_neighbors(graph, kind)
    nodes = list(adj)
    if not nodes:
        return {}
    idx = {n: i for i, n in enumerate(nodes)}
    # symmetric-ish: for directed use in-degree (prestige) — eigenvector of A^T
    x = [1.0 / len(nodes)] * len(nodes)
    indeg = {n: [] for n in nodes}
    for n in nodes:
        for m in adj[n]:
            indeg[m].append(n)
    for _ in range(max_iter):
        y = [0.0] * len(nodes)
        for n in nodes:
            y[idx[n]] = sum(x[idx[p]] for p in indeg[n])
        s = sum(y)
        if s == 0:
            break
        y = [v / s for v in y]
        delta = max(abs(a - b) for a, b in zip(x, y))
        x = y
        if delta < tol:
            break
    return {n: round(x[i], 6) for i, n in enumerate(nodes)}


def katz_centrality(
    graph: Graph,
    alpha: float = 0.1,
    kind: EdgeKind = EdgeKind.CALL,
    max_iter: int = 1000,
    tol: float = 1e-9,
) -> Dict[str, float]:
    """Katz centrality: influence with a constant baseline term."""
    adj = out_neighbors(graph, kind)
    nodes = list(adj)
    if not nodes:
        return {}
    idx = {n: i for i, n in enumerate(nodes)}
    # Katz: x = alpha A^T x + beta * 1  (beta=1)
    x = [1.0] * len(nodes)
    for _ in range(max_iter):
        y = [1.0] * len(nodes)
        for n in nodes:
            for m in adj[n]:
                y[idx[m]] += alpha * x[idx[n]]
        s = max(abs(v) for v in y) or 1.0
        y = [v / s for v in y]
        if max(abs(a - b) for a, b in zip(x, y)) < tol:
            x = y
            break
        x = y
    return {n: round(x[i], 6) for i, n in enumerate(nodes)}


def hits(
    graph: Graph,
    kind: EdgeKind = EdgeKind.CALL,
    max_iter: int = 100,
    tol: float = 1e-9,
) -> Tuple[Dict[str, float], Dict[str, float]]:
    """HITS hubs and authorities (power iteration of A A^T and A^T A)."""
    adj = out_neighbors(graph, kind)
    nodes = list(adj)
    if not nodes:
        return {}, {}
    idx = {n: i for i, n in enumerate(nodes)}
    auth = [1.0] * len(nodes)
    hub = [1.0] * len(nodes)
    for _ in range(max_iter):
        # authorities = A^T hubs
        new_auth = [0.0] * len(nodes)
        for n in nodes:
            for m in adj[n]:
                new_auth[idx[m]] += hub[idx[n]]
        # hubs = A authorities
        new_hub = [0.0] * len(nodes)
        for n in nodes:
            for m in adj[n]:
                new_hub[idx[n]] += auth[idx[m]]
        sa = sum(new_auth) or 1.0
        sh = sum(new_hub) or 1.0
        new_auth = [v / sa for v in new_auth]
        new_hub = [v / sh for v in new_hub]
        da = max(abs(a - b) for a, b in zip(auth, new_auth))
        dh = max(abs(a - b) for a, b in zip(hub, new_hub))
        auth, hub = new_auth, new_hub
        if da < tol and dh < tol:
            break
    return ({n: round(auth[i], 6) for i, n in enumerate(nodes)},
            {n: round(hub[i], 6) for i, n in enumerate(nodes)})


# ---------------------------------------------------------------------------
# Least-cost attack paths (Dijkstra)
# ---------------------------------------------------------------------------
def weighted_shortest_paths(
    graph: Graph,
    sources: Sequence[str],
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
    cost_fn: Optional[Callable[[str, str], float]] = None,
) -> Dict[str, Tuple[float, List[str]]]:
    """Least-cost path (and cost) from any source to each target (Dijkstra).

    Returns ``{target: (cost, [src, ..., target])}`` for reachable targets.
    """
    import heapq

    costs = edge_costs(graph, kind)
    if cost_fn is None:
        cost_fn = lambda s, d: costs.get((s, d), 1.0)  # noqa: E731

    adj = out_neighbors(graph, kind)
    sources = set(sources)
    best: Dict[str, Tuple[float, List[str]]] = {}
    # multi-source Dijkstra: seed all sources
    heap: List[Tuple[float, str, List[str]]] = [(0.0, s, [s]) for s in sources if s in adj]
    heapq.heapify(heap)
    seen: Dict[str, float] = {s: 0.0 for s, _, _ in heap}
    target_set = set(targets)
    while heap:
        cost, node, path = heapq.heappop(heap)
        if node in target_set and node not in best:
            best[node] = (cost, path)
            if len(best) == len(target_set & set(adj)):
                break
        if seen.get(node, float("inf")) < cost:
            continue
        for m in adj.get(node, []):
            step = max(cost_fn(node, m), 1e-6)
            nc = cost + step
            if m not in seen or nc < seen[m]:
                seen[m] = nc
                heapq.heappush(heap, (nc, m, path + [m]))
    return best


# ---------------------------------------------------------------------------
# Min vertex cut (Menger / max-flow on the vertex-split graph)
# ---------------------------------------------------------------------------
def min_vertex_cut(
    graph: Graph,
    sources: Sequence[str],
    targets: Sequence[str],
    kind: EdgeKind = EdgeKind.CALL,
) -> Tuple[int, List[str]]:
    """Minimum set of vertices separating ``sources`` from ``targets``.

    Vertex-split each node (capacity 1; sources/targets infinite), then run
    Edmonds-Karp max-flow. The cut vertices are the saturated split edges on the
    source side of the residual graph (Menger's theorem: max-flow = min-cut).
    """
    adj = out_neighbors(graph, kind)
    nodes = [n for n in adj]
    if not nodes:
        return 0, []
    sources, targets = set(sources), set(targets)

    # super source/sink and split ids
    S, T = "__SRC__", "__SNK__"
    vin = {n: f"{n}#in" for n in nodes}
    vout = {n: f"{n}#out" for n in nodes}
    caps: Dict[Tuple[str, str], int] = {}
    neigh: Dict[str, List[str]] = {S: [], T: []}

    def add(u, v, cap):
        caps[(u, v)] = caps.get((u, v), 0) + cap
        neigh.setdefault(u, []).append(v)
        neigh.setdefault(v, []).append(u)

    for n in nodes:
        neigh.setdefault(vin[n], [])
        neigh.setdefault(vout[n], [])
        cap = 10**9 if (n in sources or n in targets) else 1
        add(vin[n], vout[n], cap)
        for m in adj[n]:
            add(vout[n], vin[m], 10**9)
    for s in sources:
        if s in vin:
            add(S, vin[s], 10**9)
    for t in targets:
        if t in vin:
            add(vout[t], T, 10**9)

    # Edmonds-Karp
    flow: Dict[Tuple[str, str], int] = {}
    total = 0
    while True:
        parent: Dict[str, str] = {S: S}
        res: Dict[str, int] = {S: 10**9}
        queue = [S]
        for u in queue:
            for v in neigh.get(u, []):
                if v in parent:
                    continue
                residual = caps.get((u, v), 0) - flow.get((u, v), 0)
                if residual > 0:
                    parent[v] = u
                    res[v] = residual
                    queue.append(v)
                    if v == T:
                        break
            if T in parent:
                break
        if T not in parent:
            break
        # bottleneck along the augmenting path
        pushed = 10**9
        v = T
        while v != S:
            pushed = min(pushed, res[v])
            v = parent[v]
        v = T
        while v != S:
            u = parent[v]
            flow[(u, v)] = flow.get((u, v), 0) + pushed
            flow[(v, u)] = flow.get((v, u), 0) - pushed
            v = u
        total += pushed

    # source side of the cut (reachable in residual graph from S)
    reachable = {S}
    stack = [S]
    while stack:
        u = stack.pop()
        for v in neigh.get(u, []):
            if v not in reachable and caps.get((u, v), 0) - flow.get((u, v), 0) > 0:
                reachable.add(v)
                stack.append(v)

    cut = [n for n in nodes
           if vin[n] in reachable and vout[n] not in reachable
           and n not in sources and n not in targets]
    # A flow of >= INF means some source is directly adjacent to a target: the
    # minimum number of *internal* vertices separating them is zero.
    if total >= 10**9:
        return 0, []
    return total, cut
