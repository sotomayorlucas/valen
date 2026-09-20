//! Topological kernels over the IR graph (persistent homology + Mapper).
//!
//! We treat the graph as a filtered 1-dimensional complex (vertices + weighted
//! edges). Over this filtration:
//!
//! * **H0** (connected components) is computed with a union--find forest; the
//!   barcode records the weight at which components merge.
//! * **H1** (cycles) is the fundamental cycle basis: every non-tree edge in the
//!   minimum spanning forest closes a cycle, which is born at that edge's
//!   weight and never dies (there are no 2-cells in the 1-skeleton).
//!
//! The **Mapper** algorithm builds the navigable "manifold": choose a filter
//! function `f : V -> R`, cover its image with overlapping intervals, cluster
//! each fiber into connected components, and return the nerve (a graph whose
//! nodes are clusters).

use crate::graph::{EdgeKind, Graph};
use std::collections::{HashMap, HashSet, VecDeque};

/// A 1-dimensional persistent-homology bar: a feature born at `birth` that dies
/// at `death` (`f64::INFINITY` for features that never die).
#[derive(Debug, Clone)]
pub struct Bar {
    pub birth: f64,
    pub death: f64,
}

/// A cycle (an H1 generator): an ordered list of node indices plus its birth
/// weight. The closing edge is the last-to-first node.
#[derive(Debug, Clone)]
pub struct Cycle {
    pub birth: f64,
    pub nodes: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct Homology {
    pub beta0: usize,
    pub beta1: usize,
    pub h0_bars: Vec<Bar>,
    pub h1_cycles: Vec<Cycle>,
}

#[derive(Debug, Clone)]
pub struct MapperCluster {
    pub id: usize,
    pub nodes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MapperResult {
    pub clusters: Vec<MapperCluster>,
    /// Nerve edges as (cluster id, cluster id).
    pub nerve: Vec<(usize, usize)>,
}

struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        UnionFind { parent: (0..n).collect(), rank: vec![0; n] }
    }

    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut cur = x;
        while self.parent[cur] != cur {
            let next = self.parent[cur];
            self.parent[cur] = root;
            cur = next;
        }
        root
    }

    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra == rb {
            return;
        }
        if self.rank[ra] < self.rank[rb] {
            self.parent[ra] = rb;
        } else if self.rank[ra] > self.rank[rb] {
            self.parent[rb] = ra;
        } else {
            self.parent[rb] = ra;
            self.rank[ra] += 1;
        }
    }
}

/// Undirected, deduplicated edges (node-index pairs) with weight, sorted
/// ascending. Deduplication is essential: for an *undirected* filtration,
/// `u -> v` and `v -> u` are the same edge and must not be counted twice (a
/// double edge would otherwise be read as a spurious 2-cycle).
fn weighted_edges(graph: &Graph, kind: EdgeKind) -> Vec<(usize, usize, f64)> {
    let index = graph.node_index();
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut edges: Vec<(usize, usize, f64)> = Vec::new();
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
        let key = if a < b { (a, b) } else { (b, a) };
        if !seen.insert(key) {
            continue;
        }
        let w = e
            .attrs
            .get("weight")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);
        edges.push((a, b, w));
    }
    edges.sort_by(|x, y| x.2.partial_cmp(&y.2).unwrap_or(std::cmp::Ordering::Equal));
    edges
}

/// BFS in the spanning forest, returning the node path from `start` to `goal`.
fn forest_path(forest: &[Vec<usize>], start: usize, goal: usize) -> Vec<usize> {
    let mut parent: HashMap<usize, usize> = HashMap::new();
    let mut queue = VecDeque::new();
    parent.insert(start, start);
    queue.push_back(start);
    while let Some(node) = queue.pop_front() {
        if node == goal {
            break;
        }
        for &nb in &forest[node] {
            if !parent.contains_key(&nb) {
                parent.insert(nb, node);
                queue.push_back(nb);
            }
        }
    }
    let mut path = vec![goal];
    let mut cur = goal;
    while cur != start {
        match parent.get(&cur) {
            Some(&p) => {
                path.push(p);
                cur = p;
            }
            None => break,
        }
    }
    path.reverse();
    path
}

/// Persistent homology of the 1-skeleton of the graph over the given edge kind.
///
/// `beta0` counts connected components among the nodes that actually participate
/// in the subgraph (isolated IR nodes of other kinds are excluded); `beta1`
/// counts independent cycles.
pub fn homology(graph: &Graph, kind: EdgeKind) -> Homology {
    let edges = weighted_edges(graph, kind);
    let n = graph.nodes.len();

    let mut uf = UnionFind::new(n);
    let mut forest: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut h0_bars = Vec::new();
    let mut h1_cycles = Vec::new();
    let mut active: HashSet<usize> = HashSet::new();

    for (u, v, w) in edges {
        active.insert(u);
        active.insert(v);
        let (ru, rv) = (uf.find(u), uf.find(v));
        if ru != rv {
            uf.union(u, v);
            forest[u].push(v);
            forest[v].push(u);
            h0_bars.push(Bar { birth: 0.0, death: w });
        } else {
            let mut path = forest_path(&forest, u, v);
            path.push(u); // close the cycle back to the start
            h1_cycles.push(Cycle { birth: w, nodes: path });
        }
    }

    let mut roots: HashSet<usize> = HashSet::new();
    for &node in &active {
        roots.insert(uf.find(node));
    }
    let beta0 = roots.len();
    let beta1 = h1_cycles.len();

    Homology { beta0, beta1, h0_bars, h1_cycles }
}

/// Build the undirected adjacency over the given edge kind (deduplicated).
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
            continue;
        }
        adj.entry(a).or_default().push(b);
        adj.entry(b).or_default().push(a);
    }
    for v in adj.values_mut() {
        v.sort_unstable();
        v.dedup();
    }
    adj
}

/// Mapper over a filter function `f` (indexed by node order).
///
/// The cover is `num_intervals` overlapping intervals over the filter range;
/// each fiber is split into connected components of the induced subgraph.
pub fn mapper(
    graph: &Graph,
    kind: EdgeKind,
    filter: &[f64],
    num_intervals: usize,
    overlap: f64,
) -> MapperResult {
    let adj = adjacency(graph, kind);
    let n = graph.nodes.len();

    let mut clusters: Vec<MapperCluster> = Vec::new();
    let mut node_to_clusters: HashMap<usize, Vec<usize>> = HashMap::new();

    if n == 0 || num_intervals == 0 {
        return MapperResult { clusters, nerve: Vec::new() };
    }

    let fmin = filter.iter().cloned().fold(f64::INFINITY, f64::min);
    let fmax = filter.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let range = (fmax - fmin).max(1e-12);
    let overlap = overlap.clamp(0.0, 0.99);
    let length = range / (num_intervals as f64 - overlap * (num_intervals as f64 - 1.0));
    let step = length * (1.0 - overlap);

    let mut next_id = 0usize;
    for i in 0..num_intervals {
        let lo = fmin + i as f64 * step;
        let hi = lo + length;

        // Fiber: nodes whose filter value lies in [lo, hi].
        let fiber: Vec<usize> = (0..n).filter(|&v| filter[v] >= lo && filter[v] <= hi).collect();

        // Connected components of the induced subgraph.
        let mut visited: HashSet<usize> = HashSet::new();
        for &start in &fiber {
            if visited.contains(&start) {
                continue;
            }
            let mut comp: Vec<usize> = Vec::new();
            let mut queue = VecDeque::new();
            queue.push_back(start);
            visited.insert(start);
            while let Some(node) = queue.pop_front() {
                comp.push(node);
                if let Some(neighbors) = adj.get(&node) {
                    for &nb in neighbors {
                        if !visited.contains(&nb) && filter[nb] >= lo && filter[nb] <= hi {
                            visited.insert(nb);
                            queue.push_back(nb);
                        }
                    }
                }
            }
            let id = next_id;
            next_id += 1;
            for &node in &comp {
                node_to_clusters.entry(node).or_default().push(id);
            }
            clusters.push(MapperCluster {
                id,
                nodes: comp.iter().map(|&v| graph.nodes[v].id.clone()).collect(),
            });
        }
    }

    // Nerve: clusters sharing at least one original node.
    let mut nerve_set: HashSet<(usize, usize)> = HashSet::new();
    for ids in node_to_clusters.values() {
        for a in 0..ids.len() {
            for b in a + 1..ids.len() {
                let (x, y) = (ids[a], ids[b]);
                nerve_set.insert(if x < y { (x, y) } else { (y, x) });
            }
        }
    }
    let mut nerve: Vec<(usize, usize)> = nerve_set.into_iter().collect();
    nerve.sort_unstable();

    MapperResult { clusters, nerve }
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

    #[test]
    fn triangle_has_one_cycle() {
        let g = make(&["0", "1", "2"], &[("0", "1"), ("1", "2"), ("0", "2")]);
        let h = homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 1);
        assert_eq!(h.h1_cycles.len(), 1);
    }

    #[test]
    fn tree_has_no_cycles() {
        let g = make(&["0", "1", "2", "3"], &[("0", "1"), ("1", "2"), ("1", "3")]);
        let h = homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 1);
        assert_eq!(h.beta1, 0);
    }

    #[test]
    fn two_components_and_two_cycles() {
        // Two disconnected triangles.
        let g = make(
            &["a", "b", "c", "d", "e", "f"],
            &[("a", "b"), ("b", "c"), ("a", "c"), ("d", "e"), ("e", "f"), ("d", "f")],
        );
        let h = homology(&g, EdgeKind::Call);
        assert_eq!(h.beta0, 2);
        assert_eq!(h.beta1, 2);
    }

    #[test]
    fn mapper_nerve_connects_overlapping_fibers() {
        // Path 0-1-2-3-4 with a linear filter [0,1,2,3,4].
        let g = make(&["0", "1", "2", "3", "4"], &[("0", "1"), ("1", "2"), ("2", "3"), ("3", "4")]);
        let filter = vec![0.0, 1.0, 2.0, 3.0, 4.0];
        let m = mapper(&g, EdgeKind::Call, &filter, 3, 0.5);
        assert!(!m.clusters.is_empty());
        // The nerve of a connected path should be connected (>=1 edge).
        assert!(!m.nerve.is_empty());
    }
}
