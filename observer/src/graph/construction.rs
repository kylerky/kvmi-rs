mod provenance;
use provenance::*;

use async_std::sync::Receiver;

use super::entities::*;

use std::collections::HashMap;

pub async fn construct(rx: Receiver<(Entity, Event, Entity)>) {
    let mut provenance = ProvenanceGraph::new();
    let mut pids = HashMap::new();
    let mut files = HashMap::new();
    let mut net_endpoints = HashMap::new();
    while let Some((subject, event, object)) = rx.recv().await {
        let subject = match subject {
            Entity::Process(process) => {
                get_procs(
                    &mut pids,
                    &mut files,
                    &mut provenance,
                    process,
                    event.timestamp,
                )
                .0
            }
            _ => panic!("Unexpected variant of subject"),
        };

        match object {
            Entity::File(File { name }) => {
                let object = *files.entry(name.clone()).or_insert_with(|| {
                    provenance.add_node(TaggedEntity {
                        entity: Entity::File(File { name }),
                        data_ttag: TrustTag::Benign,
                        code_ttag: TrustTag::Benign,
                        ctag: ConfidTag::Public,
                    })
                });
                match event.access {
                    EventType::Write => {
                        provenance.add_log(subject, object, event);
                    }
                    EventType::Read | EventType::Exec => {
                        provenance.add_log(object, subject, event);
                    }
                    _ => (),
                };
            }
            Entity::NetworkEndpoint(NetworkEndpoint { addr }) => {
                let _object = *net_endpoints.entry(addr.clone()).or_insert_with(|| {
                    provenance.add_node(TaggedEntity {
                        entity: Entity::NetworkEndpoint(NetworkEndpoint { addr }),
                        data_ttag: TrustTag::Unknown,
                        code_ttag: TrustTag::Unknown,
                        ctag: ConfidTag::Public,
                    })
                });
            }
            _ => panic!("Unexpected variant of object"),
        };
        // prop
    }
}

fn get_procs(
    pids: &mut HashMap<u64, NodeIdx>,
    files: &mut HashMap<String, NodeIdx>,
    provenance: &mut ProvenanceGraph,
    process: Process,
    timestamp: u64,
) -> (NodeIdx, NodeIdx) {
    let parent_node = *pids.entry(process.ppid).or_insert_with(|| {
        let p_entity = Entity::Process(Process {
            pid: process.ppid,
            ppid: 0,
            name: String::new(),
        });
        provenance.add_node(TaggedEntity {
            entity: p_entity,
            data_ttag: TrustTag::Benign,
            code_ttag: TrustTag::Benign,
            ctag: ConfidTag::Public,
        })
    });
    let node = *pids
        .entry(process.pid)
        .and_modify(|e| {
            provenance[*e].entity = Entity::Process(process.clone());
        })
        .or_insert_with(|| {
            let node = provenance.add_node(TaggedEntity {
                entity: Entity::Process(process.clone()),
                data_ttag: TrustTag::Benign,
                code_ttag: TrustTag::Benign,
                ctag: ConfidTag::Public,
            });
            provenance.add_log(
                parent_node,
                node,
                Event {
                    access: EventType::Fork,
                    timestamp,
                },
            );

            let file = *files.entry(process.name.clone()).or_insert_with(|| {
                provenance.add_node(TaggedEntity {
                    entity: Entity::File(File { name: process.name }),
                    data_ttag: TrustTag::Benign,
                    code_ttag: TrustTag::Benign,
                    ctag: ConfidTag::Public,
                })
                // TODO: propExec
            });
            provenance.add_log(
                file,
                node,
                Event {
                    access: EventType::Exec,
                    timestamp,
                },
            );
            // TODO: propFork
            node
        });

    (node, parent_node)
}
