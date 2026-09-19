//! Spectral kernels over the IR graph.
//!
//! F2 will add Fiedler-vector / spectral-embedding extraction (via a LAPACK or
//! power-iteration backend). For now this module exposes the combinatorial
//! Laplacian in CSR form, which is the input to every spectral signal.

use crate::graph::{EdgeKind, Graph};
use std::collections::HashMap;

/// A sparse symmetric matrix in CSR format.
#[derive(Debug, Clone)]
pub struct Csr {
    pub n: usize,
    pub indptr: Vec<usize>,
    pub indices: Vec<usize>,
    pub data: Vec<f64>,
}

/// Build the combinatorial graph Laplacian `L = D - A` over a chosen edge kind.
///
/// * `kind` selects which edges participate (e.g. `Call` for the call graph or
///   `Data` for the data-flow graph).
/// * `symmetric` treats every edge as undirected (the default for the Laplacian).
pub fn laplacian_csr(graph: &Graph, kind: EdgeKind, symmetric: bool) -> Csr {
    let index: HashMap<&str, usize> = graph.node_index();
    let n = graph.nodes.len();

    let mut degree = vec![0usize; n];
    let mut edges: Vec<(usize, usize)> = Vec::new();

    for e in &graph.edges {
        if e.kind != kind {
            continue;
        }
        let (Some(&a), Some(&b)) = (index.get(e.src.as_str()), index.get(e.dst.as_str())) else {
            continue;
        };
        edges.push((a, b));
        degree[a] += 1;
        if symmetric {
            degree[b] += 1;
        }
    }

    // Assemble as a coordinate list, then sort into CSR by row.
    let mut coo: Vec<(usize, usize)> = Vec::with_capacity(edges.len() * 2);
    let mut vals: Vec<f64> = Vec::with_capacity(edges.len() * 2);
    for &(a, b) in &edges {
        coo.push((a, b));
        vals.push(-1.0);
        if symmetric {
            coo.push((b, a));
            vals.push(-1.0);
        }
    }
    for i in 0..n {
        if degree[i] > 0 {
            coo.push((i, i));
            vals.push(degree[i] as f64);
        }
    }

    // Stable sort by (row, col).
    let mut order: Vec<usize> = (0..coo.len()).collect();
    order.sort_by_key(|&i| (coo[i].0, coo[i].1));

    let mut indptr = vec![0usize; n + 1];
    let mut indices = Vec::with_capacity(order.len());
    let mut data = Vec::with_capacity(order.len());
    for &i in &order {
        let (r, c) = coo[i];
        indices.push(c);
        data.push(vals[i]);
        indptr[r + 1] += 1;
    }
    for i in 0..n {
        indptr[i + 1] += indptr[i];
    }

    Csr {
        n,
        indptr,
        indices,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, EdgeKind, Graph, Node, NodeKind};

    fn graph() -> Graph {
        let nodes = vec![
            Node { id: "a".into(), kind: NodeKind::Function, label: "a".into(), file: "".into(), line: 0, end_line: 0, attrs: Default::default() },
            Node { id: "b".into(), kind: NodeKind::Function, label: "b".into(), file: "".into(), line: 0, end_line: 0, attrs: Default::default() },
            Node { id: "c".into(), kind: NodeKind::Function, label: "c".into(), file: "".into(), line: 0, end_line: 0, attrs: Default::default() },
        ];
        let edges = vec![
            Edge { src: "a".into(), dst: "b".into(), kind: EdgeKind::Call, attrs: Default::default() },
            Edge { src: "b".into(), dst: "c".into(), kind: EdgeKind::Call, attrs: Default::default() },
        ];
        Graph { meta: Default::default(), nodes, edges }
    }

    #[test]
    fn laplacian_degrees_on_diagonal() {
        let lap = laplacian_csr(&graph(), EdgeKind::Call, true);
        assert_eq!(lap.n, 3);
        // degrees: a=1, b=2, c=1 -> diagonal = [1, 2, 1]
        for r in 0..lap.n {
            let row = &lap.data[lap.indptr[r]..lap.indptr[r + 1]];
            let diag = lap.indices[lap.indptr[r]..lap.indptr[r + 1]]
                .iter()
                .zip(row)
                .find(|(c, _)| **c == r)
                .map(|(_, v)| *v)
                .unwrap();
            assert_eq!(diag, [1.0, 2.0, 1.0][r]);
        }
    }

    #[test]
    fn json_roundtrip_from_python_shape() {
        let json = r#"{
            "meta": {"language": "python"},
            "nodes": [{"id":"a","kind":"function","label":"foo","file":"","line":1,"end_line":2,"attrs":{}}],
            "edges": [{"src":"a","dst":"b","kind":"call","attrs":{}}]
        }"#;
        let g = Graph::from_json(json).unwrap();
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(g.nodes[0].kind, NodeKind::Function);
    }
}
