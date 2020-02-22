use super::provenance::*;
use super::CMD_EXE;

use crate::graph::entities::*;

pub fn read(subject: &mut TaggedEntity, object: &mut TaggedEntity) {
    match &subject.entity {
        Entity::Process(Process { name, .. }) if name == CMD_EXE => {
            prop(&mut object.data_ttag, &mut subject.code_ttag);
            prop(&mut object.data_ttag, &mut subject.data_ttag);
            prop(&mut object.ctag, &mut subject.ctag);
        }
        _ => {
            prop(&mut object.data_ttag, &mut subject.data_ttag);
            prop(&mut object.ctag, &mut subject.ctag);
        }
    }
}

pub fn write(subject: &mut TaggedEntity, object: &mut TaggedEntity) {
    prop(&mut subject.data_ttag, &mut object.data_ttag);
    prop(&mut subject.ctag, &mut object.ctag);
}

pub fn exec(subject: &mut TaggedEntity, object: &mut TaggedEntity) {
    prop(&mut object.data_ttag, &mut subject.data_ttag);
    prop(&mut object.data_ttag, &mut subject.code_ttag);
    prop(&mut object.ctag, &mut subject.ctag);
}

#[inline]
fn prop<T: PartialOrd + Copy>(from: &mut T, to: &mut T) {
    if to < from {
        *to = *from;
    }
}
