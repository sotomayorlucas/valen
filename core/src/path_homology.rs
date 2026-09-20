//! Directed path homology (Grigor'yan–Lin–Muranov–Yau) — the directed analogue of
//! the persistent homology in `topology.rs`.
//!
//! For a digraph, an *allowed* `n`-path is a sequence `v0→v1→…→vn` of edges. The
//! boundary `∂` sends an allowed path to the alternating sum of its vertex
//! deletions, but a term may be a *non-allowed* path, so `∂` does not map allowed
//! paths into allowed paths. GLMY restrict to the subspace `Ω_n^∂` of allowed
//! paths whose boundary is again allowed, and define
//! `H_n = ker(∂|Ω_n^∂) / im(∂|Ω_{n+1}^∂)`.
//!
//! We compute `H_0` and `H_1` over the reals by dense Gaussian elimination. This
//! resolves C2 directly (no symmetrization): a directed 2-cycle `A→B→A` has
//! `H_1 = 1`, whereas the undirected homology collapses it to a single edge
//! (`H_1 = 0`).

use crate::graph::{EdgeKind, Graph};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct PathHomology {
    pub beta0: usize,
    pub beta1: usize,
    pub vertices: usize,
    pub edges: usize,
    pub paths2: usize,
}

/// Rank of a dense matrix via Gaussian elimination with partial pivoting.
fn rank(mut m: Vec<Vec<f64>>) -> usize {
    if m.is_empty() {
        return 0;
    }
    let rows = m.len();
    let cols = m[0].len();
    let mut r = 0usize;
    for c in 0..cols {
        // find pivot
        let mut pivot = None;
        for i in r..rows {
            if m[i][c].abs() > 1e-9 {
                pivot = Some(i);
                break;
            }
        }
        let Some(p) = pivot else { continue };
        m.swap(r, p);
        let pv = m[r][c];
        for i in 0..rows {
            if i != r && m[i][c].abs() > 1e-12 {
                let f = m[i][c] / pv;
                for k in c..cols {
                    m[i][k] -= f * m[r][k];
                }
            }
        }
        r += 1;
        if r == rows {
            break;
        }
    }
    r
}

/// Directed, deduplicated 1-paths (edge index) over the chosen edge kind.
fn directed_edges(graph: &Graph, kind: EdgeKind) -> (Vec<usize>, Vec<(usize, usize)>) {
    let index = graph.node_index();
    let mut active: Vec<usize> = Vec::new();
    let mut seen_vertices: HashSet<usize> = HashSet::new();
    let mut edges: Vec<(usize, usize)> = Vec::new();
    let mut seen_edges: HashSet<(usize, usize)> = HashSet::new();
    for e in &graph.edges {
        if e.kind != kind {
            continue;
        }
        let (Some(&a), Some(&b)) = (index.get(e.src.as_str()), index.get(e.dst.as_str())) else {
            continue;
        };
        if a == b {
            continue;
        }
        if !seen_vertices.insert(a) {
            // already added
        } else {
            active.push(a);
        }
        if !seen_vertices.insert(b) {
        } else {
            active.push(b);
        }
        if seen_edges.insert((a, b)) {
            edges.push((a, b));
        }
    }
    active.sort_unstable();
    (active, edges)
}

/// Directed path homology `H_0`, `H_1`.
pub fn path_homology(graph: &Graph, kind: EdgeKind) -> PathHomology {
    let (active, edges) = directed_edges(graph, kind);
    let n = active.len();
    let m = edges.len();
    if n == 0 {
        return PathHomology { beta0: 0, beta1: 0, vertices: 0, edges: 0, paths2: 0 };
    }
    let local: HashMap<usize, usize> = active.iter().enumerate().map(|(i, &v)| (v, i)).collect();
    let eidx: HashMap<(usize, usize), usize> =
        edges.iter().enumerate().map(|(i, &e)| (e, i)).collect();

    // ∂1 : R^E -> R^V  (column e=(u,v): -1 at u, +1 at v)
    let mut d1 = vec![vec![0.0f64; m]; n];
    for (j, &(u, v)) in edges.iter().enumerate() {
        d1[local[&u]][j] = -1.0;
        d1[local[&v]][j] = 1.0;
    }
    let rank1 = rank(d1);
    let beta0 = n - rank1;
    let ker1 = m - rank1; // dim ker ∂1 = undirected cycle rank of the directed multigraph

    // Ω2^∂ : allowed 2-paths whose boundary is again allowed. ∂(u,v,w) =
    // (v,w) - (u,w) + (u,v); (v,w),(u,v) are allowed by construction, so the
    // condition is that the *long* edge (u,w) is allowed and non-degenerate
    // (u ≠ w): a degenerate middle term is not a regular path.
    let mut paths2: Vec<(usize, usize, usize)> = Vec::new();
    for &(u, v) in &edges {
        for &(v2, w) in &edges {
            if v2 != v {
                continue;
            }
            if u != w && eidx.contains_key(&(u, w)) {
                paths2.push((u, v, w));
            }
        }
    }

    // ∂2 : R^P -> R^E  (column (u,v,w): +1 at (v,w), -1 at (u,w), +1 at (u,v))
    let mut d2 = vec![vec![0.0f64; paths2.len()]; m];
    for (j, &(u, v, w)) in paths2.iter().enumerate() {
        if let Some(&i) = eidx.get(&(v, w)) {
            d2[i][j] += 1.0;
        }
        if u != w {
            if let Some(&i) = eidx.get(&(u, w)) {
                d2[i][j] -= 1.0;
            }
        }
        if let Some(&i) = eidx.get(&(u, v)) {
            d2[i][j] += 1.0;
        }
    }
    let rank2 = rank(d2);
    let beta1 = ker1.saturating_sub(rank2);

    PathHomology { beta0, beta1, vertices: n, edges: m, paths2: paths2.len() }
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
            .map(|(a, b)| Edge {
                src: a.to_string(),
                dst: b.to_string(),
                kind: EdgeKind::Call,
                attrs: HashMap::new(),
            })
            .collect();
        Graph { meta: HashMap::new(), nodes, edges }
    }

    #[test]
    fn directed_two_cycle_has_h1() {
        // A -> B -> A: the undirected homology sees one edge (H1=0); GLMY sees 1.
        let g = make(&["A", "B"], &[("A", "B"), ("B", "A")]);
        let h = path_homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 1);
    }

    #[test]
    fn directed_three_cycle_has_h1() {
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("2", "0")]);
        let h = path_homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 1);
    }

    #[test]
    fn dag_has_no_h1() {
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2")]);
        let h = path_homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 0);
    }

    #[test]
    fn transitive_triangle_is_filled() {
        // 0->1, 1->2, 0->2: the 2-path (0,1,2) has an allowed long edge (0,2),
        // so its boundary fills the cycle: H1 = 0.
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("0", "2")]);
        let h = path_homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 0);
    }

    #[test]
    fn triangle_with_return_edge_has_h1() {
        // + 2->0: the directed 3-cycle 2->0->1->2 survives: H1 = 1.
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("0", "2"), ("2", "0")]);
        let h = path_homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 1);
    }
}
