//! `manifold-core` CLI: read the IR graph (JSON) on stdin and emit spectral +
//! geometric results (JSON) on stdout.

use manifold_core::{
    directed_laplacian, fiedler, forman_ricci, graph::{EdgeKind, Graph}, homology, mapper,
    ollivier_ricci, ollivier_ricci_sinkhorn, spectral_embedding,
};
use serde_json::{json, Value};
use std::io::{self, Read};

fn spectral_block(graph: &Graph, kind: EdgeKind) -> Value {
    let f = fiedler(graph, kind);
    let emb = spectral_embedding(graph, kind, 8);
    let d = directed_laplacian(graph, kind);
    json!({
        "lambda2": f.lambda2,
        "fiedler": f.vector,
        "embedding": {
            "eigenvalues": emb.eigenvalues,
            "eigenvectors": emb.eigenvectors,
        },
        "directed": {
            "scc_size": d.scc_size,
            "lambda2": d.lambda2,
            "fiedler": d.vector,
        },
    })
}

fn geometry_block(graph: &Graph, kind: EdgeKind) -> Value {
    let oricci = ollivier_ricci(graph, kind, 0.5);
    let sinkhorn = ollivier_ricci_sinkhorn(graph, kind, 0.5, 0.05, 200);
    let fricci = forman_ricci(graph, kind);
    json!({
        "ollivier_ricci": oricci.iter().map(|e| json!({"src": e.src, "dst": e.dst, "kappa": e.kappa})).collect::<Vec<_>>(),
        "ollivier_ricci_sinkhorn": sinkhorn.iter().map(|e| json!({"src": e.src, "dst": e.dst, "kappa": e.kappa})).collect::<Vec<_>>(),
        "forman_ricci": fricci.iter().map(|e| json!({"src": e.src, "dst": e.dst, "kappa": e.kappa})).collect::<Vec<_>>(),
    })
}

fn topology_block(graph: &Graph, kind: EdgeKind) -> Value {
    let hom = homology(graph, kind);
    let f = fiedler(graph, kind);
    let m = mapper(graph, kind, &f.vector, 8, 0.3);

    let cycles: Vec<Value> = hom
        .h1_cycles
        .iter()
        .map(|c| {
            json!({
                "birth": c.birth,
                "nodes": c.nodes.iter().map(|&i| graph.nodes[i].id.clone()).collect::<Vec<_>>(),
            })
        })
        .collect();

    json!({
        "beta0": hom.beta0,
        "beta1": hom.beta1,
        "h0_bars": hom.h0_bars.iter().map(|b| json!({"birth": b.birth, "death": b.death})).collect::<Vec<_>>(),
        "h1_cycles": cycles,
        "mapper": {
            "clusters": m.clusters.iter().map(|c| json!({"id": c.id, "nodes": c.nodes})).collect::<Vec<_>>(),
            "nerve": m.nerve,
        },
    })
}

fn main() -> io::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;

    let graph: Graph = serde_json::from_str(&input)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let node_order: Vec<String> = graph.nodes.iter().map(|n| n.id.clone()).collect();

    let out = json!({
        "node_order": node_order,
        "spectral": {
            "call": spectral_block(&graph, EdgeKind::Call),
            "data": spectral_block(&graph, EdgeKind::Data),
            "control": spectral_block(&graph, EdgeKind::Control),
        },
        "geometry": {
            "call": geometry_block(&graph, EdgeKind::Call),
            "data": geometry_block(&graph, EdgeKind::Data),
            "control": geometry_block(&graph, EdgeKind::Control),
        },
        "topology": {
            "call": topology_block(&graph, EdgeKind::Call),
            "data": topology_block(&graph, EdgeKind::Data),
            "control": topology_block(&graph, EdgeKind::Control),
        },
    });

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
