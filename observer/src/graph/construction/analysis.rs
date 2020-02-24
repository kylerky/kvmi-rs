use super::provenance::*;

use petgraph::algo;
use petgraph::prelude::*;
use petgraph::visit::{self, Control, DfsEvent, IntoEdgesDirected, Reversed};

use crate::graph::entities::Entity;

use std::collections::HashMap;

const HI_COST: u32 = 100;
pub const THRESHOLD: u32 = 4 * HI_COST;

pub(super) fn backward_path(
    graph: &ProvGraph,
    sources: Vec<NodeIdx>,
) -> Option<(u32, Vec<NodeIdx>)> {
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

            get_cost(get_tags(source, target))
        },
        |_| 0,
    )
}

pub(super) fn forward_construction(
    provenance: &ProvenanceGraph,
    path: Vec<NodeIdx>,
    threshold: u32,
) -> Option<ProvGraph> {
    use ConfidTag::*;
    use Control::*;
    use DfsEvent::*;
    use TrustTag::*;

    path.last().map(|entry| {
        let mut result = Graph::new();
        let entry_node = result.add_node(provenance[*entry].clone());

        let mut distances = HashMap::new();
        distances.insert(*entry, (0, entry_node));

        visit::depth_first_search::<_, _, _, Control<()>>(
            provenance.get_flow(),
            Some(*entry),
            |event| {
                match event {
                    TreeEdge(source, target) => {
                        let source_ent = &provenance[source];
                        let target_ent = &provenance[target];

                        let tags = get_tags(target_ent, source_ent);
                        let mut cost = get_cost(tags);
                        if cost == HI_COST {
                            cost = match (source_ent.ctag, tags) {
                                (Secret, (Unknown, _, _, _)) | (Secret, (_, Unknown, _, _)) => 0,
                                _ => HI_COST,
                            }
                        }
                        let (dist, src_node) = *distances.get(&source).unwrap();
                        let dist = cost + dist;
                        if dist > threshold {
                            return Prune;
                        }
                        let tgt_node = result.add_node(provenance[target].clone());
                        distances.insert(target, (dist, tgt_node));
                        result.add_edge(src_node, tgt_node, Log::from(vec![]));
                    }
                    BackEdge(source, target) | CrossForwardEdge(source, target) => {
                        let (_, src_node) = *distances.get(&source).unwrap();
                        let (_, tgt_node) = *distances.get(&target).unwrap();
                        result.add_edge(src_node, tgt_node, Log::from(vec![]));
                    }
                    _ => (),
                }
                Continue
            },
        );

        result
    })
}

fn get_tags(e1: &TaggedEntity, e2: &TaggedEntity) -> (TrustTag, TrustTag, TrustTag, TrustTag) {
    let e1_dt = e1.data_ttag;
    let mut e1_ct = e1.code_ttag;
    let e2_dt = e2.data_ttag;
    let mut e2_ct = e2.code_ttag;
    match e1 {
        TaggedEntity {
            entity: Entity::Process(_),
            ..
        } => (),
        _ => e1_ct = e1_dt,
    }
    match e2 {
        TaggedEntity {
            entity: Entity::Process(_),
            ..
        } => (),
        _ => e2_ct = e2_dt,
    }
    (e1_ct, e1_dt, e2_ct, e2_dt)
}

fn get_cost(tags: (TrustTag, TrustTag, TrustTag, TrustTag)) -> u32 {
    use TrustTag::*;
    match tags {
        (_, Unknown, Unknown, Unknown) | (Unknown, _, Unknown, Unknown) => 1,
        (_, Unknown, _, _) | (Unknown, _, _, _) => 0,
        _ => HI_COST,
    }
}
