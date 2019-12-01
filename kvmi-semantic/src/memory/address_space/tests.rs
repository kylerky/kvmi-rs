#![allow(clippy::ptr_arg)]

use mockall::predicate::*;
use mockall::{mock, Sequence};

use async_std::sync::Arc;

use super::{AddressSpace, IA32eVirtual};
use crate::Error;

use pretty_assertions::assert_eq;

type AddressType = u64;

mock! {
    pub KVMIPhysical {
        fn new(dom: kvmi::Domain) -> Self;
        fn get_dom(&self) -> &kvmi::Domain;
        async fn read(&self, addr: AddressType, sz: usize) -> Result<Vec<u8>, Error>;
        async fn write(&self, addr: AddressType, data: Vec<u8>) -> Result<(), Error>;
        fn from(dom: kvmi::Domain) -> Self;
    }
    trait AddressSpace {
        type AddrT = AddressType;
    }
}

const PAGE_ENTRY_SZ: usize = 8;
const ADDR_MASK: u64 = 0xff8;

#[async_std::test]
async fn ia32e_translation_l2() {
    let v_addr = 0xffff_a18f_8076_5540u64;

    let mut seq = Sequence::new();
    let mut p_space = MockKVMIPhysical::default();

    let mut expect = |lx_entry, ptbpt, level| {
        let mut entry = vec![];
        entry.extend_from_slice(&u64::to_ne_bytes(lx_entry));
        p_space
            .expect_read()
            .once()
            .in_sequence(&mut seq)
            .with(
                eq(ptbpt + ((v_addr >> (level * 9)) & ADDR_MASK)),
                eq(PAGE_ENTRY_SZ),
            )
            .return_once(|_, _| Ok(entry));
    };

    let l4_ptbpt = 0x000_0000_001a_d000u64;
    let l4_entry = 0xa00_0000_0193_3863u64;
    let l3_ptbpt = 0x000_0000_0193_3000u64;
    expect(l4_entry, l4_ptbpt, 4u64);
    let l3_entry = 0xa00_0000_0193_b863u64;
    let l2_ptbpt = 0x000_0000_0193_b000u64;
    expect(l3_entry, l3_ptbpt, 3u64);
    // bit 7 (PS) set, so tranlsation should end here
    let l2_entry = 0x8a00_0001_3ba0_08e3u64;
    expect(l2_entry, l2_ptbpt, 2u64);

    p_space.expect_read().never().in_sequence(&mut seq);

    let p_space = Arc::new(p_space);
    let v_space = IA32eVirtual::new(p_space, l4_ptbpt);

    let result = v_space.translate_v2p(v_addr).await.unwrap();
    assert_eq!(Some(0x1_3bb6_5540), result);
}
