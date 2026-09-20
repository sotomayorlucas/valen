//! Directed spectral kernel: Chung's directed Laplacian.
//!
//! The symmetrized combinatorial Laplacian discards the *direction* of control
//! and data flow. Chung's directed Laplacian restores it: for a strongly
//! connected digraph with transition matrix `P` and stationary (Perron) vector
//! `phi`, define
//!
//! ```text
//!   L = I - ( Phi^{1/2} P Phi^{-1/2} + Phi^{-1/2} P^T Phi^{1/2} ) / 2
//! ```
//!
//! where `Phi = diag(phi)`. `L` is symmetric, positive semidefinite, and its
//! second-smallest eigenvalue is the *directed algebraic connectivity*. A
//! strongly connected component is required; for a DAG (no directed cycle) the
//! signal is undefined, which itself is meaningful (there is no direction to
//! preserve).

use crate::graph::{EdgeKind, Graph};
use nalgebra::{DMatrix, DVector, SymmetricEigen};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct DirectedSpectral {
    /// Size of the largest strongly connected component analyzed.
    pub scc_size: usize,
    /// Directed algebraic connectivity (None if no SCC of size >= 2 exists).
    pub lambda2: Option<f64>,
    /// Directed Fiedler vector over the full node order (zero outside the SCC).
    pub vector: Vec<f64>,
}

fn directed_adjacency(graph: &Graph, kind: EdgeKind) -> (DMatrix<f64>, Vec<Vec<usize>>, Vec<Vec<usize>>) {
    let index = graph.node_index();
    let n = graph.nodes.len();
    let mut a = DMatrix::<f64>::zeros(n, n);
    let mut fwd: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut bwd: Vec<Vec<usize>> = vec![Vec::new(); n];
    for e in &graph.edges {
        if e.kind != kind {
            continue;
        }
        let (Some(&i), Some(&j)) = (index.get(e.src.as_str()), index.get(e.dst.as_str())) else {
            continue;
        };
        if i == j {
            continue;
        }
        let w = e.attrs.get("weight").and_then(|v| v.as_f64()).unwrap_or(1.0);
        a[(i, j)] += w;
        fwd[i].push(j);
        bwd[j].push(i);
    }
    (a, fwd, bwd)
}

/// Strongly connected component containing `start` (forward reach ∩ backward reach).
fn scc_of(start: usize, fwd: &[Vec<usize>], bwd: &[Vec<usize>]) -> HashSet<usize> {
    let reach = |adj: &[Vec<usize>], from: usize| -> HashSet<usize> {
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        seen.insert(from);
        q.push_back(from);
        while let Some(v) = q.pop_front() {
            for &nb in &adj[v] {
                if seen.insert(nb) {
                    q.push_back(nb);
                }
            }
        }
        seen
    };
    reach(fwd, start)
        .intersection(&reach(bwd, start))
        .cloned()
        .collect()
}

fn largest_scc(fwd: &[Vec<usize>], bwd: &[Vec<usize>]) -> Vec<usize> {
    let n = fwd.len();
    let mut assigned = vec![false; n];
    let mut best: Vec<usize> = Vec::new();
    for start in 0..n {
        if assigned[start] {
            continue;
        }
        let scc = scc_of(start, fwd, bwd);
        if scc.len() > best.len() {
            best = scc.iter().cloned().collect();
        }
        for &v in &scc {
            assigned[v] = true;
        }
    }
    best.sort_unstable();
    best
}

/// Compute the stationary distribution of a transition matrix via power
/// iteration with a small teleportation (ensures convergence on periodic
/// chains, e.g. a directed cycle).
fn stationary(transition: &DMatrix<f64>) -> DVector<f64> {
    let n = transition.nrows();
    if n == 0 {
        return DVector::zeros(0);
    }
    let eps = 0.01;
    let mut p = DVector::from_element(n, 1.0 / n as f64);
    let teleport = eps / n as f64;
    for _ in 0..2000 {
        let q = transition.transpose() * &p;
        let mut next = q * (1.0 - eps);
        for i in 0..n {
            next[i] += teleport;
        }
        let s = next.sum();
        if s <= 0.0 {
            break;
        }
        next /= s;
        let diff = (&next - &p).norm();
        p = next;
        if diff < 1e-12 {
            break;
        }
    }
    p
}

/// Chung's directed Laplacian and directed algebraic connectivity.
pub fn directed_laplacian(graph: &Graph, kind: EdgeKind) -> DirectedSpectral {
    let (adj, fwd, bwd) = directed_adjacency(graph, kind);
    let n = graph.nodes.len();
    let scc = largest_scc(&fwd, &bwd);

    if scc.len() < 2 {
        return DirectedSpectral { scc_size: scc.len(), lambda2: None, vector: vec![0.0; n] };
    }

    let m = scc.len();

    // Restricted transition matrix P (row-stochastic over the SCC).
    let mut p = DMatrix::<f64>::zeros(m, m);
    for (r, &i) in scc.iter().enumerate() {
        let deg: f64 = (0..n).map(|j| adj[(i, j)]).sum();
        if deg <= 0.0 {
            continue;
        }
        for (c, &j) in scc.iter().enumerate() {
            p[(r, c)] = adj[(i, j)] / deg;
        }
    }

    let phi = stationary(&p);
    let mut sqrt_phi = DVector::zeros(m);
    let mut inv_sqrt_phi = DVector::zeros(m);
    for k in 0..m {
        let v = phi[k].max(1e-12);
        sqrt_phi[k] = v.sqrt();
        inv_sqrt_phi[k] = 1.0 / v.sqrt();
    }

    // L = I - 0.5 * (Phi^{1/2} P Phi^{-1/2} + Phi^{-1/2} P^T Phi^{1/2})
    let mut l = DMatrix::<f64>::identity(m, m);
    for r in 0..m {
        for c in 0..m {
            let first = sqrt_phi[r] * p[(r, c)] * inv_sqrt_phi[c];
            let second = inv_sqrt_phi[r] * p[(c, r)] * sqrt_phi[c];
            l[(r, c)] -= 0.5 * (first + second);
        }
    }

    let eig = SymmetricEigen::new(l);
    let mut ascending: Vec<usize> = (0..m).collect();
    ascending.sort_by(|&i, &j| eig.eigenvalues[i].partial_cmp(&eig.eigenvalues[j]).unwrap());
    let idx = ascending
        .iter()
        .copied()
        .find(|&i| eig.eigenvalues[i] > 1e-9)
        .unwrap_or(ascending[0]);
    let lambda2 = eig.eigenvalues[idx];

    // Map the directed Fiedler vector back to the full node order.
    let mut vector = vec![0.0; n];
    for (k, &global) in scc.iter().enumerate() {
        vector[global] = eig.eigenvectors[(idx, k)];
    }

    DirectedSpectral { scc_size: m, lambda2: Some(lambda2), vector }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, Node, NodeKind};
    use std::collections::HashMap;

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

    #[test]
    fn directed_cycle_has_positive_connectivity() {
        // 0 -> 1 -> 2 -> 0 is strongly connected: directed connectivity > 0.
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("2", "0")]);
        let d = directed_laplacian(&g, EdgeKind::Call);
        assert_eq!(d.scc_size, 3);
        assert!(d.lambda2.unwrap() > 0.0);
    }

    #[test]
    fn directed_dag_has_no_scc() {
        // A pure DAG (0 -> 1 -> 2) has no directed cycle: signal is undefined.
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2")]);
        let d = directed_laplacian(&g, EdgeKind::Call);
        assert!(d.lambda2.is_none());
    }

    #[test]
    fn largest_scc_detects_cycle_in_mixed_graph() {
        // A cycle among {0,1,2} plus a dangling 3 -> 2.
        let g = make(&["0", "1", "2", "3"], &[("0", "1"), ("1", "2"), ("2", "0"), ("3", "2")]);
        let d = directed_laplacian(&g, EdgeKind::Call);
        assert_eq!(d.scc_size, 3);
        assert!(d.lambda2.unwrap() > 0.0);
    }
}
