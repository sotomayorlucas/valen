//! Centrality kernels: betweenness centrality and PageRank.
//!
//! Betweenness identifies the *bridge* nodes in an attack graph (the sole
//! connector between trust domains); PageRank ranks node importance. Both
//! complement the Fiedler cut and Forman--Ricci curvature already exposed.

use std::collections::{HashMap, VecDeque};

use crate::graph::{EdgeKind, Graph};

fn adjacency(graph: &Graph, kind: EdgeKind) -> HashMap<String, Vec<String>> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for n in &graph.nodes {
        adj.entry(n.id.clone()).or_default();
    }
    for e in graph.edges.iter().filter(|e| e.kind == kind) {
        adj.entry(e.src.clone()).or_default().push(e.dst.clone());
    }
    adj
}

/// Brandes' algorithm for betweenness centrality (directed graph).
/// Returns ``[(node_id, score), ...]`` sorted by score descending.
pub fn betweenness_centrality(graph: &Graph, kind: EdgeKind) -> Vec<(String, f64)> {
    let adj = adjacency(graph, kind);
    let ids: Vec<String> = graph.nodes.iter().map(|n| n.id.clone()).collect();
    let mut bc: HashMap<String, f64> = HashMap::new();
    for id in &ids {
        bc.insert(id.clone(), 0.0);
    }

    for s in &ids {
        let mut stack: Vec<String> = Vec::new();
        let mut pred: HashMap<String, Vec<String>> = HashMap::new();
        let mut sigma: HashMap<String, f64> = HashMap::new();
        let mut dist: HashMap<String, i64> = HashMap::new();
        for id in &ids {
            sigma.insert(id.clone(), 0.0);
            dist.insert(id.clone(), -1);
        }
        sigma.insert(s.clone(), 1.0);
        dist.insert(s.clone(), 0);
        let mut queue = VecDeque::new();
        queue.push_back(s.clone());

        while let Some(v) = queue.pop_front() {
            stack.push(v.clone());
            if let Some(neighbors) = adj.get(&v) {
                for w in neighbors {
                    if dist[w] < 0 {
                        dist.insert(w.clone(), dist[&v] + 1);
                        queue.push_back(w.clone());
                    }
                    if dist[w] == dist[&v] + 1 {
                        sigma.insert(w.clone(), sigma[w] + sigma[&v]);
                        pred.entry(w.clone()).or_default().push(v.clone());
                    }
                }
            }
        }

        let mut delta: HashMap<String, f64> = HashMap::new();
        for id in &ids {
            delta.insert(id.clone(), 0.0);
        }
        while let Some(w) = stack.pop() {
            if let Some(preds) = pred.get(&w) {
                for v in preds {
                    let contribution = (sigma[v] / sigma[&w]) * (1.0 + delta[&w]);
                    *delta.entry(v.clone()).or_insert(0.0) += contribution;
                }
            }
            if &w != s {
                *bc.entry(w.clone()).or_insert(0.0) += delta[&w];
            }
        }
    }

    let mut result: Vec<(String, f64)> = bc.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    result
}

/// PageRank (power iteration, damping 0.85).
/// Returns ``[(node_id, score), ...]`` sorted by score descending.
pub fn pagerank(
    graph: &Graph,
    kind: EdgeKind,
    iterations: usize,
    damping: f64,
) -> Vec<(String, f64)> {
    let adj = adjacency(graph, kind);
    let ids: Vec<String> = graph.nodes.iter().map(|n| n.id.clone()).collect();
    let n = ids.len() as f64;
    if n == 0.0 {
        return vec![];
    }

    let mut pr: HashMap<String, f64> = HashMap::new();
    for id in &ids {
        pr.insert(id.clone(), 1.0 / n);
    }

    for _ in 0..iterations {
        let mut new_pr: HashMap<String, f64> = HashMap::new();
        for id in &ids {
            new_pr.insert(id.clone(), (1.0 - damping) / n);
        }
        for id in &ids {
            let out = adj.get(id).map(|v| v.len()).unwrap_or(0) as f64;
            if out > 0.0 {
                let share = pr[id] / out;
                for w in &adj[id] {
                    *new_pr.entry(w.clone()).or_insert(0.0) += damping * share;
                }
            } else {
                let share = pr[id] / n;
                for id2 in &ids {
                    *new_pr.entry(id2.clone()).or_insert(0.0) += damping * share;
                }
            }
        }
        pr = new_pr;
    }

    let mut result: Vec<(String, f64)> = pr.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    result
}
