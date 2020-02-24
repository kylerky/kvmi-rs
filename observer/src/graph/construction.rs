#[cfg(test)]
mod tests;

mod provenance;
pub(crate) use provenance::*;

pub(crate) mod analysis;
use analysis::THRESHOLD;

pub(crate) mod alarms;

mod propagation;

use async_std::sync::{Receiver, Sender};

use super::entities::*;

use std::collections::HashMap;

use regex::RegexSet;

struct Constructor {
    provenance: ProvenanceGraph,
    pids: HashMap<u64, NodeIdx>,
    files: HashMap<String, NodeIdx>,
    net_endpoints: HashMap<String, NodeIdx>,
    secrets: RegexSet,
}

impl Constructor {
    fn new(secrets: RegexSet) -> Self {
        Self {
            provenance: ProvenanceGraph::new(),
            pids: HashMap::new(),
            files: HashMap::new(),
            net_endpoints: HashMap::new(),
            secrets,
        }
    }
}

pub async fn construct(
    log_rx: Receiver<(Entity, Event, Entity)>,
    graph_tx: Sender<ProvGraph>,
    secrets: RegexSet,
) {
    let mut constructor = Constructor::new(secrets);
    while let Some((subject, event, object)) = log_rx.recv().await {
        let alerts = gen_alert(&mut constructor, subject, event, object);
        if !alerts.is_empty() {
            if let Some(graph) = analyse(&constructor, alerts) {
                graph_tx.send(graph).await;
            }
        }
    }
}

fn analyse(constructor: &Constructor, alerts: Vec<NodeIdx>) -> Option<ProvGraph> {
    analysis::backward_path(constructor.provenance.get_flow(), alerts)
        .map(|(cost, path)| {
            analysis::forward_construction(&constructor.provenance, path, THRESHOLD + cost)
        })
        .flatten()
}

fn gen_alert(
    constructor: &mut Constructor,
    subject: Entity,
    event: Event,
    object: Entity,
) -> Vec<NodeIdx> {
    let mut alerts = vec![];

    let subject = match subject {
        Entity::Process(process) => {
            let (subject, _, detected) = get_procs(
                &mut constructor.pids,
                &mut constructor.files,
                &mut constructor.provenance,
                process,
                event.timestamp,
                &constructor.secrets,
            );
            if let Some(detected) = detected {
                alerts.push(detected);
            }
            subject
        }
        _ => panic!("Unexpected variant of subject"),
    };

    match object {
        Entity::File(File { name }) => {
            let object = get_file(
                &mut constructor.provenance,
                &mut constructor.files,
                name,
                &constructor.secrets,
            );

            let provenance = &mut constructor.provenance;
            match event.access {
                EventType::Write => {
                    provenance.add_log(subject, object, event);

                    let (subject_entity, object_entity) =
                        provenance.index_twice_mut(subject, object);
                    if trigger_write(subject_entity, object_entity) {
                        alerts.push(object);
                    }
                }
                EventType::Read => {
                    provenance.add_log(object, subject, event);

                    let (subject_entity, object_entity) =
                        provenance.index_twice_mut(subject, object);
                    if trigger_read(subject_entity, object_entity) {
                        alerts.push(subject);
                    }
                }
                EventType::Exec => {
                    provenance.add_log(object, subject, event);

                    let (subject_entity, object_entity) =
                        provenance.index_twice_mut(subject, object);
                    if trigger_exec(subject_entity, object_entity) {
                        alerts.push(subject);
                    }
                }
                _ => (),
            };
        }
        Entity::NetworkEndpoint(NetworkEndpoint { addr }) => {
            let object = get_network_endpoint(
                &mut constructor.provenance,
                &mut constructor.net_endpoints,
                addr,
            );

            let provenance = &mut constructor.provenance;
            if let EventType::Open = event.access {
                provenance.add_log(subject, object, event.clone());
                provenance.add_log(object, subject, event);

                let (subject_entity, object_entity) = provenance.index_twice_mut(subject, object);
                if trigger_read(subject_entity, object_entity) {
                    alerts.push(subject);
                }
                if trigger_write(subject_entity, object_entity) {
                    alerts.push(object);
                }
            }
        }
        _ => panic!("Unexpected variant of object"),
    };
    alerts
}

fn trigger_read(subject: &mut TaggedEntity, object: &mut TaggedEntity) -> bool {
    let alert = alarms::read(subject, object);
    propagation::read(subject, object);
    alert
}

fn trigger_write(subject: &mut TaggedEntity, object: &mut TaggedEntity) -> bool {
    let alert = alarms::write(subject, object);
    propagation::write(subject, object);
    alert
}

fn trigger_exec(subject: &mut TaggedEntity, object: &mut TaggedEntity) -> bool {
    let alert = alarms::exec(subject, object);
    propagation::exec(subject, object);
    alert
}

const CMD_EXE: &str = r"\\Windows\\System32\\cmd.exe";
fn get_procs(
    pids: &mut HashMap<u64, NodeIdx>,
    files: &mut HashMap<String, NodeIdx>,
    provenance: &mut ProvenanceGraph,
    process: Process,
    timestamp: u64,
    secrets: &RegexSet,
) -> (NodeIdx, NodeIdx, Option<NodeIdx>) {
    let mut alert = None;
    let parent_node = *pids.entry(process.ppid).or_insert_with(|| {
        let p_entity = Entity::Process(Process {
            pid: process.ppid,
            ppid: 0,
            name: String::new(),
        });
        provenance.add_node(TaggedEntity {
            entity: p_entity,
            data_ttag: TrustTag::BenignAuth,
            code_ttag: TrustTag::BenignAuth,
            ctag: ConfidTag::Public,
        })
    });

    let mut process2 = process.clone();
    if process2.name != CMD_EXE {
        process2.name = String::from(process.name.rsplit(r"\\").next().unwrap());
    }
    let node = *pids
        .entry(process.pid)
        .and_modify(|e| {
            provenance[*e].entity = Entity::Process(process2.clone());
        })
        .or_insert_with(|| {
            let data_ttag = provenance[parent_node].data_ttag;
            let code_ttag = provenance[parent_node].code_ttag;
            let ctag = provenance[parent_node].ctag;

            let node = provenance.add_node(TaggedEntity {
                entity: Entity::Process(process2),
                data_ttag,
                code_ttag,
                ctag,
            });
            provenance.add_log(
                parent_node,
                node,
                Event {
                    access: EventType::Fork,
                    timestamp,
                },
            );

            let file = get_file(provenance, files, process.name, secrets);
            provenance.add_log(
                file,
                node,
                Event {
                    access: EventType::Exec,
                    timestamp,
                },
            );

            let (subject_entity, object_entity) = provenance.index_twice_mut(node, file);
            if trigger_exec(subject_entity, object_entity) {
                alert = Some(file);
            }

            node
        });

    (node, parent_node, alert)
}

fn get_network_endpoint(
    provenance: &mut ProvenanceGraph,
    net_endpoints: &mut HashMap<String, NodeIdx>,
    addr: String,
) -> NodeIdx {
    let (data_ttag, code_ttag) = if addr.starts_with("127.") {
        (TrustTag::BenignAuth, TrustTag::BenignAuth)
    } else {
        (TrustTag::Unknown, TrustTag::Unknown)
    };

    *net_endpoints.entry(addr.clone()).or_insert_with(|| {
        provenance.add_node(TaggedEntity {
            entity: Entity::NetworkEndpoint(NetworkEndpoint { addr }),
            data_ttag,
            code_ttag,
            ctag: ConfidTag::Private,
        })
    })
}

fn get_file(
    provenance: &mut ProvenanceGraph,
    files: &mut HashMap<String, NodeIdx>,
    name: String,
    secrets: &RegexSet,
) -> NodeIdx {
    let ctag = if secrets.is_match(&name) {
        ConfidTag::Secret
    } else {
        ConfidTag::Public
    };
    *files.entry(name.clone()).or_insert_with(|| {
        provenance.add_node(TaggedEntity {
            entity: Entity::File(File { name }),
            data_ttag: TrustTag::BenignAuth,
            code_ttag: TrustTag::BenignAuth,
            ctag,
        })
    })
}
