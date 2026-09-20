//! Scalability benchmark: time each kernel as a function of |E|.
//!
//! Emits CSV `kernel,edges,nodes,ms` for a geometric progression of synthetic
//! graphs. Dense kernels (spectral, directed Laplacian) are capped because they
//! materialize an n x n matrix --- that cap is itself the finding.

use manifold_core::{
    directed_laplacian, fiedler, forman_ricci, graph::{Edge, EdgeKind, Graph, Node},
    homology, mapper, ollivier_ricci, ollivier_ricci_sinkhorn,
};
use std::collections::HashMap;
use std::time::Instant;

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 16
}

fn gen_graph(n: usize, m: usize, seed: u64) -> Graph {
    let nodes: Vec<Node> = (0..n)
        .map(|i| Node {
            id: format!("{i}"),
            kind: manifold_core::NodeKind::Function,
            label: format!("{i}"),
            file: String::new(),
            line: 0,
            end_line: 0,
            attrs: HashMap::new(),
        })
        .collect();
    let mut state = seed;
    let mut edges = Vec::with_capacity(m);
    for _ in 0..m {
        let a = (lcg(&mut state) as usize) % n;
        let b = (lcg(&mut state) as usize) % n;
        if a == b {
            continue;
        }
        edges.push(Edge {
            src: format!("{a}"),
            dst: format!("{b}"),
            kind: EdgeKind::Call,
            attrs: HashMap::new(),
        });
    }
    Graph { meta: HashMap::new(), nodes, edges }
}

fn time_ms<T>(f: impl FnOnce() -> T) -> f64 {
    let t = Instant::now();
    let _ = f();
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    println!("kernel,edges,nodes,ms");

    // Sparse, near-linear kernels.
    for &m in &[1_000usize, 10_000, 100_000] {
        let g = gen_graph((m / 2).max(10), m, 0x1234_5678);
        let n = g.nodes.len();
        println!("forman,{m},{n},{:.2}", time_ms(|| forman_ricci(&g, EdgeKind::Call)));
        println!("homology,{m},{n},{:.2}", time_ms(|| homology(&g, EdgeKind::Call)));
        println!("mapper,{m},{n},{:.2}", time_ms(|| {
            let f: Vec<f64> = (0..n).map(|i| (i as f64) / (n as f64)).collect();
            mapper(&g, EdgeKind::Call, &f, 8, 0.3)
        }));
    }

    // Entropic transport (Sinkhorn): per-edge, heavier.
    for &m in &[1_000usize, 2_000, 5_000] {
        let g = gen_graph((m / 2).max(10), m, 0x9abc_def0);
        let n = g.nodes.len();
        println!("sinkhorn,{m},{n},{:.2}", time_ms(|| ollivier_ricci_sinkhorn(&g, EdgeKind::Call, 0.5, 0.05, 20)));
    }

    // Exact transport (LP per edge): the slow baseline.
    for &m in &[200usize, 500, 1_000] {
        let g = gen_graph((m / 2).max(10), m, 0x0f0f_0f0f);
        let n = g.nodes.len();
        println!("ollivier_exact,{m},{n},{:.2}", time_ms(|| ollivier_ricci(&g, EdgeKind::Call, 0.5)));
    }

    // Dense kernels (n x n): cubic, capped.
    for &n in &[300usize, 600, 1_200] {
        let g = gen_graph(n, 3 * n, 0xdead_beef);
        let m = g.edges.len();
        println!("spectral_fiedler,{m},{n},{:.2}", time_ms(|| fiedler(&g, EdgeKind::Call)));
        println!("directed_laplacian,{m},{n},{:.2}", time_ms(|| directed_laplacian(&g, EdgeKind::Call)));
    }
}

