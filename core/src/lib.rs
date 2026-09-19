//! MANIFOLD numeric core.
//!
//! This crate mirrors the Python IR (see `manifold/ir.py`) and hosts the
//! performance-critical kernels:
//!
//! * `graph`     — typed graph mirror (serde JSON, drops straight in from Python)
//! * `spectral`  — Laplacian, degree/adjacency (Fiedler vector & spectral
//!                 embedding arrive in F2 with a LAPACK backend)
//! * `topology`  — persistent homology / Mapper (F3)
//! * `algebra`   — abstract-interpretation lattices & taint lattice (F4)

pub mod graph;
pub mod spectral;

pub use graph::{Edge, EdgeKind, Graph, Node, NodeKind};
pub use spectral::laplacian_csr;
