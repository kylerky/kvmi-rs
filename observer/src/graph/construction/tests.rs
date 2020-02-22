use crate::graph::entities::*;

use super::analysis;
use super::provenance::*;
use super::Constructor;

use regex::RegexSet;

use pretty_assertions::assert_eq;

use petgraph::algo;

fn gen_logs() -> Vec<(Entity, Event, Entity)> {
    // event parameters
    let ppid = 575;

    let entry_ip = "192.168.2.2";

    let hole = r"\\prog\\hole.exe";
    let hole_pid = 576;
    let hole_time = 100;
    let hole_entity = Entity::Process(Process {
        pid: hole_pid,
        ppid,
        name: hole.to_string(),
    });

    let trojan = r"\\file\\trojan.exe";
    let trojan_pid = 578;
    let trojan_time = 220;
    let trojan_entity = Entity::Process(Process {
        pid: trojan_pid,
        ppid: hole_pid,
        name: trojan.to_string(),
    });
    let trojan_file = Entity::File(File {
        name: trojan.to_string(),
    });

    // secret file set up

    let read_time = 475;
    let read_name = r"\\file\\info.secret";
    let secret_file = Entity::File(File {
        name: read_name.to_string(),
    });

    let leak_time = 680;
    let leak_ip = "192.168.2.4";
    let leak_endpoint = Entity::NetworkEndpoint(NetworkEndpoint {
        addr: leak_ip.to_string(),
    });

    // construct events
    vec![
        (
            hole_entity.clone(),
            Event {
                access: EventType::Open,
                timestamp: hole_time,
            },
            Entity::NetworkEndpoint(NetworkEndpoint {
                addr: entry_ip.to_string(),
            }),
        ),
        (
            hole_entity,
            Event {
                access: EventType::Write,
                timestamp: trojan_time,
            },
            trojan_file,
        ),
        (
            trojan_entity.clone(),
            Event {
                access: EventType::Read,
                timestamp: read_time,
            },
            secret_file,
        ),
        (
            trojan_entity,
            Event {
                access: EventType::Open,
                timestamp: leak_time,
            },
            leak_endpoint,
        ),
    ]
}

fn gen_ref_graph() -> (ProvGraph, NodeIdx, (u32, Vec<NodeIdx>)) {
    let logs = gen_logs();

    let hole_entity = logs[0].0.clone();
    let entry_endpoint = logs[0].2.clone();
    let trojan_file = logs[1].2.clone();
    let trojan_entity = logs[2].0.clone();
    let secret_file = logs[2].2.clone();
    let leak_ip = logs[3].2.clone();

    let (ppid, hole_file) = match hole_entity.clone() {
        Entity::Process(Process { ppid, name, .. }) => (ppid, Entity::File(File { name })),
        _ => panic!("Expect an Entity::Process, found {:?}", hole_entity),
    };

    let mut graph = ProvGraph::new();

    let unknown_private = TaggedEntity {
        entity: hole_entity,
        data_ttag: TrustTag::Unknown,
        code_ttag: TrustTag::BenignAuth,
        ctag: ConfidTag::Private,
    };
    let hole_entity = graph.add_node(unknown_private.clone());

    let mut entity = unknown_private.clone();
    entity.entity = entry_endpoint;
    let entry_endpoint = graph.add_node(entity);

    let mut entity = unknown_private;
    entity.entity = trojan_file;
    let trojan_file = graph.add_node(entity);

    let unknown_secret = TaggedEntity {
        entity: trojan_entity,
        data_ttag: TrustTag::Unknown,
        code_ttag: TrustTag::Unknown,
        ctag: ConfidTag::Secret,
    };

    let entity = unknown_secret.clone();
    let trojan_entity = graph.add_node(entity);

    let mut entity = unknown_secret.clone();
    entity.entity = secret_file;
    entity.data_ttag = TrustTag::BenignAuth;
    let secret_file = graph.add_node(entity);

    let mut entity = unknown_secret;
    entity.entity = leak_ip;
    let leak_ip = graph.add_node(entity);

    let mut auth_pub = TaggedEntity {
        entity: Entity::Process(Process {
            pid: ppid,
            ppid: 0,
            name: String::from(""),
        }),
        code_ttag: TrustTag::BenignAuth,
        data_ttag: TrustTag::BenignAuth,
        ctag: ConfidTag::Public,
    };
    let parent = graph.add_node(auth_pub.clone());

    auth_pub.entity = hole_file;
    let hole_file = graph.add_node(auth_pub);

    for (s, t) in [
        (parent, hole_entity),
        (hole_file, hole_entity),
        (hole_entity, entry_endpoint),
        (entry_endpoint, hole_entity),
        (hole_entity, trojan_file),
        (trojan_file, trojan_entity),
        (hole_entity, trojan_entity),
        (secret_file, trojan_entity),
        (trojan_entity, leak_ip),
        (leak_ip, trojan_entity),
    ]
    .iter()
    {
        graph.add_edge(*s, *t, Log::from(vec![]));
    }
    (
        graph,
        leak_ip,
        (2, vec![leak_ip, trojan_entity, hole_entity, entry_endpoint]),
    )
}

#[test]
fn test_gen_alert() {
    let secrets_pat = [r".*\.secret$"];
    let secrets = RegexSet::new(&secrets_pat).unwrap();
    let mut constructor = Constructor::new(secrets);

    let mut logs = gen_logs();
    let num = logs.len();
    let leak_endpoint = logs[num - 1].2.clone();

    // send the events
    for (subject, event, object) in logs.drain(..num - 1) {
        let res = super::gen_alert(&mut constructor, subject, event, object);
        assert!(res.is_empty());
    }

    // assert the alert
    let (subject, event, object) = logs.drain(..).next().expect("Should have one event left");
    let res = super::gen_alert(&mut constructor, subject, event, object);
    assert_eq!(res.len(), 1);
    assert_eq!(
        TaggedEntity {
            entity: leak_endpoint,
            code_ttag: TrustTag::Unknown,
            data_ttag: TrustTag::Unknown,
            ctag: ConfidTag::Secret,
        },
        constructor.provenance[res[0]]
    );

    let (reference, _, _) = gen_ref_graph();

    assert!(algo::is_isomorphic_matching(
        constructor.provenance.get_graph(),
        &reference,
        |prov, re| {
            let mut re_node = re.clone();
            match &mut re_node {
                TaggedEntity {
                    entity: Entity::Process(Process { name, .. }),
                    ..
                } => *name = name.rsplit(r"\\").next().unwrap().to_string(),
                TaggedEntity { code_ttag, .. } => *code_ttag = prov.code_ttag,
            }
            assert_eq!(prov, &re_node);
            true
        },
        |_, _| true,
    ));
}

#[test]
fn test_backward_analysis() {
    let (reference, src, expect) = gen_ref_graph();
    let actual = analysis::backward_path(&reference, vec![src]);
    assert_eq!(actual, Some(expect));
}
