#![allow(dead_code)]

use petgraph::dot::{Config, Dot};
use petgraph::prelude::*;

use crate::graph::entities::*;

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::ops::{Index, IndexMut};

pub type IndexType = u32;
pub type NodeIdx = NodeIndex<IndexType>;
pub type EdgeIdx = EdgeIndex<IndexType>;

#[derive(Debug)]
pub enum TrustTag {
    Benign,
    Unknown,
}

#[derive(Debug)]
pub enum ConfidTag {
    Secret,
    Private,
    Public,
}

#[derive(Debug)]
pub struct TaggedEntity {
    pub entity: Entity,
    pub data_ttag: TrustTag,
    pub code_ttag: TrustTag,
    pub ctag: ConfidTag,
}

impl Display for TaggedEntity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Log {
    events: Vec<Event>,
}

impl Display for Log {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "events")
    }
}

impl From<Vec<Event>> for Log {
    fn from(events: Vec<Event>) -> Self {
        Self { events }
    }
}

type ProvGraph = DiGraph<TaggedEntity, Log, IndexType>;
pub struct ProvenanceGraph {
    flow: ProvGraph,
    edges: HashMap<(NodeIdx, NodeIdx), EdgeIdx>,
}

impl ProvenanceGraph {
    pub fn new() -> Self {
        Self {
            flow: DiGraph::new(),
            edges: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, weight: TaggedEntity) -> NodeIdx {
        self.flow.add_node(weight)
    }

    pub fn add_log(
        &mut self,
        from: NodeIndex<IndexType>,
        to: NodeIndex<IndexType>,
        weight: Event,
    ) -> EdgeIdx {
        let edges = &mut self.edges;
        let flow = &mut self.flow;
        *edges
            .entry((from, to))
            .and_modify(|e| {
                let edge = &mut flow[*e];
                edge.events.push(weight.clone());
            })
            .or_insert_with(|| flow.add_edge(from, to, Log::from(vec![weight])))
    }

    pub fn get_dot_with_config<'a>(&'a self, config: &'a [Config]) -> Dot<&'a ProvGraph> {
        Dot::with_config(&self.flow, config)
    }
}

impl Index<NodeIdx> for ProvenanceGraph {
    type Output = TaggedEntity;

    fn index(&self, idx: NodeIdx) -> &Self::Output {
        &self.flow[idx]
    }
}

impl IndexMut<NodeIdx> for ProvenanceGraph {
    fn index_mut(&mut self, idx: NodeIdx) -> &mut Self::Output {
        &mut self.flow[idx]
    }
}
