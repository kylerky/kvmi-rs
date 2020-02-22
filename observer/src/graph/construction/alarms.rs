use crate::graph::entities::*;

use super::provenance::*;

pub fn read(_subject: &TaggedEntity, _object: &TaggedEntity) -> bool {
    false
}

pub fn write(subject: &TaggedEntity, object: &TaggedEntity) -> bool {
    match (subject.ctag, subject.code_ttag, &object.entity) {
        (ConfidTag::Secret, code, Entity::NetworkEndpoint(_)) if code > TrustTag::BenignAuth => {
            true
        }
        _ => false,
    }
}

pub fn exec(_subject: &TaggedEntity, _object: &TaggedEntity) -> bool {
    false
}
