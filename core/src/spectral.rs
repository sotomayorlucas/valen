//! Spectral kernels over the IR graph.
//!
//! Implements the algebraic graph theory layer: combinatorial Laplacian,
//! algebraic connectivity / Fiedler vector, and low-dimensional spectral
//! embeddings. Eigen-decomposition uses `nalgebra`'s symmetric eigensolver
//! (dense; for very large graphs a sparse eigensolver such as LOBPCG/ARPACK
//! can be plugged in behind the same API).

use crate::graph::{EdgeKind, Graph};
use nalgebra::{DMatrix, SymmetricEigen};
use std::collections::HashMap;

/// A sparse symmetric matrix in CSR format (hand-off / export).
#[derive(Debug, Clone)]
pub struct Csr {
    pub n: usize,
    pub indptr: Vec<usize>,
    pub indices: Vec<usize>,
    pub data: Vec<f64>,
}

/// The Fiedler pair: second-smallest eigenvalue and its eigenvector.
#[derive(Debug, Clone)]
pub struct Fiedler {
    /// Algebraic connectivity `lambda_2` (the smallest positive eigenvalue).
    pub lambda2: f64,
    /// The Fiedler vector `f_2`, indexed by node order.
    pub vector: Vec<f64>,
}

/// A spectral embedding: the top `k` nontrivial eigenvalues + eigenvectors.
#[derive(Debug, Clone)]
pub struct SpectralEmbedding {
    pub eigenvalues: Vec<f64>,
    /// `eigenvectors[i]` is the node-indexed vector for `eigenvalues[i]`.
    pub eigenvectors: Vec<Vec<f64>>,
}

/// Build the combinatorial graph Laplacian `L = D - A` over a chosen edge kind.
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

    let mut coo: Vec<(usize, usize)> = Vec::with_capacity(edges.len() * 2 + n);
    let mut vals: Vec<f64> = Vec::with_capacity(edges.len() * 2 + n);
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

    Csr { n, indptr, indices, data }
}

fn laplacian_dense(graph: &Graph, kind: EdgeKind, symmetric: bool) -> DMatrix<f64> {
    let csr = laplacian_csr(graph, kind, symmetric);
    let n = csr.n;
    let mut lap = DMatrix::<f64>::zeros(n, n);
    for r in 0..n {
        for k in csr.indptr[r]..csr.indptr[r + 1] {
            lap[(r, csr.indices[k])] = csr.data[k];
        }
    }
    lap
}

/// Compute the Fiedler vector over the given edge kind.
///
/// Uses the smallest positive eigenvalue of the (symmetric) Laplacian. For a
/// connected graph this is `lambda_2`; for disconnected graphs we pick the
/// first nontrivial spectral direction.
pub fn fiedler(graph: &Graph, kind: EdgeKind) -> Fiedler {
    let lap = laplacian_dense(graph, kind, true);
    let n = lap.nrows();
    if n < 2 {
        return Fiedler { lambda2: 0.0, vector: vec![0.0; n] };
    }
    let eig = SymmetricEigen::new(lap);
    // nalgebra returns eigenvalues in *descending* order; build an ascending index.
    let mut ascending: Vec<usize> = (0..n).collect();
    ascending.sort_by(|&i, &j| eig.eigenvalues[i].partial_cmp(&eig.eigenvalues[j]).unwrap());
    let idx = ascending
        .iter()
        .copied()
        .find(|&i| eig.eigenvalues[i] > 1e-9)
        .unwrap_or(ascending[0]);
    let lambda2 = eig.eigenvalues[idx];
    let vector = eig.eigenvectors.column(idx).iter().cloned().collect();
    Fiedler { lambda2, vector }
}

/// Compute a low-dimensional spectral embedding (excluding the trivial
/// all-ones direction), i.e. the eigenvectors `f_2 .. f_{dim+1}`.
pub fn spectral_embedding(graph: &Graph, kind: EdgeKind, dim: usize) -> SpectralEmbedding {
    let lap = laplacian_dense(graph, kind, true);
    let n = lap.nrows();
    if n == 0 || dim == 0 {
        return SpectralEmbedding { eigenvalues: vec![], eigenvectors: vec![] };
    }
    let eig = SymmetricEigen::new(lap);
    let mut ascending: Vec<usize> = (0..n).collect();
    ascending.sort_by(|&i, &j| eig.eigenvalues[i].partial_cmp(&eig.eigenvalues[j]).unwrap());
    let start_idx = ascending
        .iter()
        .position(|&i| eig.eigenvalues[i] > 1e-9)
        .unwrap_or(0);
    let count = dim.min(ascending.len() - start_idx);
    let eigenvalues: Vec<f64> = ascending[start_idx..start_idx + count]
        .iter()
        .map(|&i| eig.eigenvalues[i])
        .collect();
    let eigenvectors: Vec<Vec<f64>> = ascending[start_idx..start_idx + count]
        .iter()
        .map(|&i| eig.eigenvectors.column(i).iter().cloned().collect())
        .collect();
    SpectralEmbedding { eigenvalues, eigenvectors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Edge, Node, NodeKind};
    use std::collections::HashMap;

    fn path(n: usize) -> Graph {
        let nodes: Vec<Node> = (0..n)
            .map(|i| Node {
                id: format!("{i}"),
                kind: NodeKind::Function,
                label: format!("{i}"),
                file: "".into(),
                line: 0,
                end_line: 0,
                attrs: HashMap::new(),
            })
            .collect();
        let mut edges = Vec::new();
        for i in 0..n.saturating_sub(1) {
            edges.push(Edge { src: format!("{i}"), dst: format!("{}", i + 1), kind: EdgeKind::Call, attrs: HashMap::new() });
        }
        Graph { meta: HashMap::new(), nodes, edges }
    }

    #[test]
    fn fiedler_path_p4_matches_closed_form() {
        // Algebraic connectivity of the path P_n is 2 - 2 cos(pi/n).
        let g = path(4);
        let f = fiedler(&g, EdgeKind::Call);
        let expected = 2.0 - 2.0 * (std::f64::consts::PI / 4.0).cos();
        assert!((f.lambda2 - expected).abs() < 1e-6, "got {}", f.lambda2);
        // The Fiedler vector of a path has a single sign change: the two
        // endpoints lie on opposite sides of the spectral cut.
        assert!(f.vector[0] * f.vector[3] < 0.0);
        assert!(f.vector[0] * f.vector[1] > 0.0);
    }

    #[test]
    fn embedding_dims_are_respected() {
        let g = path(5);
        let e = spectral_embedding(&g, EdgeKind::Call, 3);
        assert_eq!(e.eigenvalues.len(), 3);
        assert_eq!(e.eigenvectors.len(), 3);
        assert_eq!(e.eigenvectors[0].len(), 5);
    }

    #[test]
    fn laplacian_degrees_on_diagonal() {
        let lap = laplacian_csr(&path(3), EdgeKind::Call, true);
        assert_eq!(lap.n, 3);
        for r in 0..lap.n {
            let diag = (lap.indptr[r]..lap.indptr[r + 1])
                .filter_map(|k| (lap.indices[k] == r).then_some(lap.data[k]))
                .next()
                .unwrap();
            assert_eq!(diag, [1.0, 2.0, 1.0][r]);
        }
     }
 }

