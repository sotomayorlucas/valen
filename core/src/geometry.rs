//! Geometric kernels over the IR graph.
//!
//! Two discrete Ricci curvatures:
//!
//! * **Ollivier–Ricci** — the "metric" curvature, computed from the Wasserstein-1
//!   distance between lazy random-walk measures around each edge endpoint. It is
//!   positive on dense communities (triangles) and negative on bottlenecks.
//! * **Forman–Ricci** — the combinatorial curvature `4 - deg(u) - deg(v)` for
//!   unweighted graphs (Forman 2003). Cheap, exact, and strongly negative at
//!   high-degree hubs (chokepoints).

use crate::graph::{EdgeKind, Graph};
use minilp::{ComparisonOp, OptimizationDirection, Problem};
use nalgebra::DMatrix;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct RicciEdge {
    pub src: String,
    pub dst: String,
    pub kappa: f64,
}

/// Undirected adjacency (by node index) over the chosen edge kind.
fn adjacency(graph: &Graph, kind: EdgeKind) -> HashMap<usize, Vec<usize>> {
    let index = graph.node_index();
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for e in &graph.edges {
        if e.kind != kind {
            continue;
        }
        let (Some(&a), Some(&b)) = (index.get(e.src.as_str()), index.get(e.dst.as_str())) else {
            continue;
        };
        if a == b {
            continue; // ignore self-loops for curvature
        }
        adj.entry(a).or_default().push(b);
        adj.entry(b).or_default().push(a);
    }
    for neighbors in adj.values_mut() {
        neighbors.sort_unstable();
        neighbors.dedup();
    }
    adj
}

/// Collect unique undirected edges (by node index) over the chosen kind.
fn undirected_edges(graph: &Graph, kind: EdgeKind) -> Vec<(usize, usize, String, String)> {
    let index = graph.node_index();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut out = Vec::new();
    for e in &graph.edges {
        if e.kind != kind {
            continue;
        }
        let (Some(&a), Some(&b)) = (index.get(e.src.as_str()), index.get(e.dst.as_str())) else {
            continue;
        };
        let key = if a < b { (a, b) } else { (b, a) };
        if seen.insert(key) {
            out.push((a, b, e.src.clone(), e.dst.clone()));
        }
    }
    out
}

/// BFS shortest-path distances from `start` over the undirected adjacency.
fn bfs_distances(adj: &HashMap<usize, Vec<usize>>, start: usize) -> HashMap<usize, usize> {
    let mut dist = HashMap::new();
    let mut queue = VecDeque::new();
    dist.insert(start, 0);
    queue.push_back(start);
    while let Some(node) = queue.pop_front() {
        let d = dist[&node];
        if let Some(neighbors) = adj.get(&node) {
            for &nb in neighbors {
                if !dist.contains_key(&nb) {
                    dist.insert(nb, d + 1);
                    queue.push_back(nb);
                }
            }
        }
    }
    dist
}

/// Wasserstein-1 distance between two discrete measures (aligned vectors),
/// solved exactly as a minimum-cost transportation linear program.
fn wasserstein1(mu: &[f64], nu: &[f64], dist: &DMatrix<f64>) -> f64 {
    let m = mu.len();
    let n = nu.len();

    // One transport variable per (i, j) pair.
    let mut problem = Problem::new(OptimizationDirection::Minimize);
    let mut vars: Vec<minilp::Variable> = Vec::with_capacity(m * n);
    for i in 0..m {
        for j in 0..n {
            vars.push(problem.add_var(dist[(i, j)], (0.0, f64::INFINITY)));
        }
    }

    // Row constraints: sum_j pi(i, j) = mu(i).
    for i in 0..m {
        let coeffs: Vec<(minilp::Variable, f64)> = (0..n).map(|j| (vars[i * n + j], 1.0)).collect();
        problem.add_constraint(&coeffs, ComparisonOp::Eq, mu[i]);
    }
    // Column constraints: sum_i pi(i, j) = nu(j).
    for j in 0..n {
        let coeffs: Vec<(minilp::Variable, f64)> = (0..m).map(|i| (vars[i * n + j], 1.0)).collect();
        problem.add_constraint(&coeffs, ComparisonOp::Eq, nu[j]);
    }

    match problem.solve() {
        Ok(solution) => solution.objective(),
        Err(_) => f64::INFINITY,
    }
}

/// Entropy-regularized transport cost via the Sinkhorn (matrix scaling) fixed
/// point. As `reg -> 0` this converges to the unregularized transport cost,
/// which for the shortest-path ground metric is `W_1`. This is the fast
/// approximate alternative to the exact LP for large graphs.
fn sinkhorn_cost(mu: &[f64], nu: &[f64], dist: &DMatrix<f64>, reg: f64, iters: usize) -> f64 {
    let m = mu.len();
    let n = nu.len();
    if m == 0 || n == 0 {
        return 0.0;
    }
    let k = dist.map(|c| (-c / reg).exp());
    let mut u = vec![1.0; m];
    let mut v = vec![1.0; n];
    for _ in 0..iters {
        for i in 0..m {
            let s: f64 = (0..n).map(|j| k[(i, j)] * v[j]).sum();
            u[i] = if s > 0.0 { mu[i] / s } else { 0.0 };
        }
        for j in 0..n {
            let s: f64 = (0..m).map(|i| k[(i, j)] * u[i]).sum();
            v[j] = if s > 0.0 { nu[j] / s } else { 0.0 };
        }
    }
    let mut cost = 0.0;
    for i in 0..m {
        for j in 0..n {
            cost += u[i] * k[(i, j)] * v[j] * dist[(i, j)];
        }
    }
    cost
}

/// Lazy random-walk measure around a node: `(1-alpha)` mass on the node and
/// `alpha` mass spread uniformly over its neighbors.
fn lazy_measure(
    node: usize,
    adj: &HashMap<usize, Vec<usize>>,
    alpha: f64,
) -> HashMap<usize, f64> {
    let mut m = HashMap::new();
    m.insert(node, 1.0 - alpha);
    let neighbors = adj.get(&node).cloned().unwrap_or_default();
    if !neighbors.is_empty() {
        let w = alpha / neighbors.len() as f64;
        for &nb in &neighbors {
            *m.entry(nb).or_insert(0.0) += w;
        }
    } else {
        // Isolated node: all mass stays.
        *m.entry(node).or_insert(0.0) += alpha;
    }
    m
}

/// Ollivier–Ricci curvature of every undirected edge over the given kind.
///
/// `kappa(u,v) = 1 - W_1(m_u, m_v) / d(u,v)` with lazy random-walk measures,
/// where `W_1` is computed *exactly* via a transportation LP.
pub fn ollivier_ricci(graph: &Graph, kind: EdgeKind, alpha: f64) -> Vec<RicciEdge> {
    build_transport_instances(graph, kind, alpha)
        .into_iter()
        .map(|inst| {
            let w = wasserstein1(&inst.mu, &inst.nu, &inst.dist);
            RicciEdge { src: inst.src, dst: inst.dst, kappa: 1.0 - w / inst.d_uv }
        })
        .collect()
}

/// Approximate Ollivier–Ricci via entropy-regularized (Sinkhorn) transport.
///
/// `reg` is the regularization strength (smaller = closer to the exact `W_1`);
/// `iters` is the number of matrix-scaling iterations. This is `O(|E| * iters *
/// k^2)` for local support size `k`, avoiding the per-edge LP.
pub fn ollivier_ricci_sinkhorn(
    graph: &Graph,
    kind: EdgeKind,
    alpha: f64,
    reg: f64,
    iters: usize,
) -> Vec<RicciEdge> {
    build_transport_instances(graph, kind, alpha)
        .into_iter()
        .map(|inst| {
            let w = sinkhorn_cost(&inst.mu, &inst.nu, &inst.dist, reg, iters);
            RicciEdge { src: inst.src, dst: inst.dst, kappa: 1.0 - w / inst.d_uv }
        })
        .collect()
}

/// Per-edge transport data (marginals + ground distances) shared by the exact
/// and approximate Ollivier–Ricci solvers.
struct TransportInstance {
    src: String,
    dst: String,
    d_uv: f64,
    mu: Vec<f64>,
    nu: Vec<f64>,
    dist: DMatrix<f64>,
}

fn build_transport_instances(graph: &Graph, kind: EdgeKind, alpha: f64) -> Vec<TransportInstance> {
    let adj = adjacency(graph, kind);
    undirected_edges(graph, kind)
        .into_iter()
        .map(|(a, b, src, dst)| {
            let mu_map = lazy_measure(a, &adj, alpha);
            let nu_map = lazy_measure(b, &adj, alpha);
            let support: HashSet<usize> = mu_map.keys().chain(nu_map.keys()).cloned().collect();

            let mut dist_map: HashMap<(usize, usize), f64> = HashMap::new();
            for &x in &support {
                let d = bfs_distances(&adj, x);
                for &y in &support {
                    dist_map.insert((x, y), d.get(&y).copied().unwrap_or(usize::MAX) as f64);
                }
            }
            let d_uv = dist_map.get(&(a, b)).copied().unwrap_or(1.0).max(1.0);

            let mut xs: Vec<usize> = mu_map.keys().cloned().collect();
            xs.sort_unstable();
            let mut ys: Vec<usize> = nu_map.keys().cloned().collect();
            ys.sort_unstable();
            let mu: Vec<f64> = xs.iter().map(|x| mu_map[x]).collect();
            let nu: Vec<f64> = ys.iter().map(|y| nu_map[y]).collect();
            let dist = DMatrix::from_fn(xs.len(), ys.len(), |i, j| dist_map[&(xs[i], ys[j])]);

            TransportInstance { src, dst, d_uv, mu, nu, dist }
        })
        .collect()
}

/// Forman–Ricci curvature (unweighted): `kappa_F(u,v) = 4 - deg(u) - deg(v)`.
pub fn forman_ricci(graph: &Graph, kind: EdgeKind) -> Vec<RicciEdge> {
    let adj = adjacency(graph, kind);
    undirected_edges(graph, kind)
        .into_iter()
        .map(|(a, b, src, dst)| {
            let deg_a = adj.get(&a).map(|v| v.len()).unwrap_or(0);
            let deg_b = adj.get(&b).map(|v| v.len()).unwrap_or(0);
            RicciEdge { src, dst, kappa: 4.0 - deg_a as f64 - deg_b as f64 }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, Node, NodeKind};

    fn make(ids: &[&str], edges: &[(&str, &str)]) -> Graph {
        let nodes: Vec<Node> = ids
            .iter()
            .map(|id| Node {
                id: id.to_string(),
                kind: NodeKind::Function,
                label: id.to_string(),
                file: "".into(),
                line: 0,
                end_line: 0,
                attrs: HashMap::new(),
            })
            .collect();
        let edges: Vec<Edge> = edges
            .iter()
            .map(|(a, b)| Edge { src: a.to_string(), dst: b.to_string(), kind: EdgeKind::Call, attrs: HashMap::new() })
            .collect();
        Graph { meta: HashMap::new(), nodes, edges }
    }

    fn edge_kappa(ricci: &[RicciEdge], a: &str, b: &str) -> f64 {
        ricci
            .iter()
            .find(|e| (e.src == a && e.dst == b) || (e.src == b && e.dst == a))
            .map(|e| e.kappa)
            .unwrap()
    }

    #[test]
    fn ollivier_triangle_is_positive() {
        // K_3 edge with alpha=0.5 has kappa = 0.75 (closed form).
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("0", "2")]);
        let ricci = ollivier_ricci(&g, EdgeKind::Call, 0.5);
        let k = edge_kappa(&ricci, "0", "1");
        assert!((k - 0.75).abs() < 1e-6, "got {}", k);
    }

    #[test]
    fn sinkhorn_approximates_exact_on_triangle() {
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("0", "2")]);
        let exact = edge_kappa(&ollivier_ricci(&g, EdgeKind::Call, 0.5), "0", "1");
        let approx = edge_kappa(
            &ollivier_ricci_sinkhorn(&g, EdgeKind::Call, 0.5, 0.05, 200),
            "0",
            "1",
        );
        assert!(
            (exact - approx).abs() < 2e-2,
            "sinkhorn {approx} too far from exact {exact}"
        );
    }

    #[test]
    fn ollivier_barbell_bridge_is_negative() {
        // Two triangles joined by a bridge: the bridge edge is a chokepoint.
        let g = make(
            &["a", "b", "c", "d", "e", "f"],
            &[
                ("a", "b"), ("b", "c"), ("a", "c"), // left triangle
                ("c", "d"), // bridge
                ("d", "e"), ("e", "f"), ("d", "f"), // right triangle
            ],
        );
        let ricci = ollivier_ricci(&g, EdgeKind::Call, 0.5);
        let bridge = edge_kappa(&ricci, "c", "d");
        let triangle = edge_kappa(&ricci, "a", "b");
        assert!(bridge < 0.0, "bridge kappa = {}", bridge);
        assert!(triangle > bridge, "triangle {} should exceed bridge {}", triangle, bridge);
    }

    #[test]
    fn forman_hub_is_negative_and_single_edge_positive() {
        // Barbell bridge (deg 3,3) -> 4 - 3 - 3 = -2.
        let g = make(
            &["a", "b", "c", "d", "e", "f"],
            &[
                ("a", "b"), ("b", "c"), ("a", "c"),
                ("c", "d"),
                ("d", "e"), ("e", "f"), ("d", "f"),
            ],
        );
        let ricci = forman_ricci(&g, EdgeKind::Call);
        assert_eq!(edge_kappa(&ricci, "c", "d"), -2.0);

        // Single edge (deg 1,1) -> 4 - 1 - 1 = 2.
        let single = make(&["x", "y"], &[("x", "y")]);
        let r = forman_ricci(&single, EdgeKind::Call);
        assert_eq!(edge_kappa(&r, "x", "y"), 2.0);
    }
}
