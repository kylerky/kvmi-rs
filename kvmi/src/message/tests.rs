use super::*;

use pretty_assertions::assert_eq;

use rand::prelude::*;
use rand_pcg::Pcg64Mcg;

#[test]
fn get_registers_construct_reply() {
    let msrs_idx = vec![0xC000_0080, 0xC000_0081];
    let msg = GetRegisters::new(0, msrs_idx.clone());

    let mut rng = Pcg64Mcg::seed_from_u64(612);
    let mut expect = kvmi_get_registers_reply::default();
    unsafe {
        rng.fill_bytes(any_as_mut_u8_slice(&mut expect));
    }

    let msrs = vec![
        kvm_msr_entry {
            index: msrs_idx[0],
            reserved: 0,
            data: rng.gen(),
        },
        kvm_msr_entry {
            index: msrs_idx[1],
            reserved: 0,
            data: rng.gen(),
        },
    ];

    expect.padding = 0;
    expect.msrs.pad = 0;
    expect.msrs.nmsrs = msrs.len() as u32;

    let mut result = vec![];
    unsafe {
        result.extend(any_as_u8_slice(&expect).iter().cloned());
    }

    result.append(&mut any_vec_as_u8_vec(msrs.clone()));

    let reply = msg.construct_reply(result);
    assert_eq!(expect, *reply.get_regs());
    assert_eq!(msrs, reply.get_msrs());
}
