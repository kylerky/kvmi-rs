use super::provenance::*;

use petgraph::algo;
use petgraph::prelude::*;
use petgraph::visit::{Data, IntoEdgesDirected, Reversed};

use crate::graph::entities::Entity;

pub fn backward_path(graph: &ProvGraph, sources: Vec<NodeIdx>) -> Option<(u32, Vec<NodeIdx>)> {
    use TrustTag::*;

    let rev_graph = Reversed(graph);
    algo::astar(
        rev_graph,
        sources[0],
        |node| {
            if node != sources[0] {
                let entity = &graph[node];
                match entity {
                    TaggedEntity {
                        entity: Entity::NetworkEndpoint(_),
                        data_ttag: TrustTag::Unknown,
                        ..
                    } => return true,
                    TaggedEntity {
                        data_ttag: TrustTag::Unknown,
                        ..
                    }
                    | TaggedEntity {
                        entity: Entity::Process(_),
                        code_ttag: TrustTag::Unknown,
                        ..
                    } => {
                        if rev_graph.edges_directed(node, Outgoing).next().is_none() {
                            return true;
                        }
                    }
                    _ => (),
                }
            }
            false
        },
        |edge| {
            let source = &graph[edge.source()];
            let target = &graph[edge.target()];

            let src_dt = source.data_ttag;
            let mut src_ct = source.code_ttag;
            let tgt_dt = target.data_ttag;
            let mut tgt_ct = target.code_ttag;
            match source {
                TaggedEntity {
                    entity: Entity::Process(_),
                    ..
                } => (),
                _ => src_ct = src_dt,
            }
            match target {
                TaggedEntity {
                    entity: Entity::Process(_),
                    ..
                } => (),
                _ => tgt_ct = tgt_dt,
            }

            match (src_ct, src_dt, tgt_ct, tgt_dt) {
                (Unknown, Unknown, _, Unknown) | (Unknown, Unknown, Unknown, _) => 1,
                (_, _, _, Unknown) | (_, _, Unknown, _) => 0,
                _ => 100,
            }
        },
        |_| 0,
    )
}

pub fn forward_construction(graph: &ProvGraph, path: Vec<NodeIdx>) -> ProvGraph {
    let mut nodes: Vec<<ProvGraph as Data>::NodeWeight> =
        path.iter().map(|node| &graph[*node]).cloned().collect();

    let mut result = Graph::new();
    let nodes: Vec<NodeIdx> = nodes.drain(..).map(|node| result.add_node(node)).collect();

    let num = nodes.len();
    let edges = nodes[1..].iter().zip(nodes[..num - 1].iter());
    for (s, d) in edges {
        result.add_edge(*s, *d, Log::from(vec![]));
    }
    result
}
