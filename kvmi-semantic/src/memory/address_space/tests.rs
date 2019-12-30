#![allow(clippy::ptr_arg)]

use mockall::predicate::*;
use mockall::{mock, Sequence};

use async_std::sync::Arc;

use super::kvmi_physical::*;
use super::{AddressSpace, IA32eVirtual};
use crate::Error;
use kvmi::message::{Message, ReadPhysical, SetPageAccess};
use kvmi::PageAccessEntryBuilder;

use pretty_assertions::assert_eq;

type AddressType = u64;

mock! {
    pub KVMIPhysical {
        fn new(dom: kvmi::Domain) -> Self;
        fn get_dom(&self) -> &kvmi::Domain;
        async fn read(&self, addr: AddressType, sz: usize) -> Result<Vec<u8>, Error>;
        async fn write(&self, addr: AddressType, data: Vec<u8>) -> Result<(), Error>;
        async fn evict(&self, addr: AddressType) -> Result<(), Error>;
        async fn read_within_page(
            &self,
            key: AddressType,
            offset: usize,
            sz: usize,
        ) -> Result<Vec<u8>, Error>;
        fn from(dom: kvmi::Domain) -> Self;
    }
    trait AddressSpace {
        type AddrT = AddressType;
    }
}

mock! {
    pub Domain {
        async fn send<T: Message + 'static>(&self, mut msg: T) -> Result<T::Reply, Error>;
    }
}

const PAGE_ENTRY_SZ: usize = 8;
const ADDR_MASK: u64 = 0xff8;

const PADDR_OFFSET: u64 = 0xfff;
const PADDR_KEY: u64 = !PADDR_OFFSET;
const PHYSICAL_PAGE_SZ: usize = 1 << 12;

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
    assert_eq!(Some((0x1_3bb6_5540, 2)), result);
}

#[async_std::test]
async fn read_direct() {
    let addr = 0x3ba0_08e3u64;
    let key = addr & PADDR_KEY;
    let offset = addr & PADDR_OFFSET;
    let sz = 8;

    let mut dom = MockDomain::default();

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];

            let offset = offset as usize;
            for (i, elt) in v.iter_mut().enumerate().skip(offset).take(sz) {
                *elt = (i - offset + 1) as u8;
            }
            Ok(v)
        });

    let mut expect = vec![0u8; sz];
    for (i, elt) in expect.iter_mut().enumerate() {
        *elt = (i + 1) as u8;
    }
    let p_space = KVMIPhysical::new(dom);
    assert_eq!(
        expect,
        p_space.read(addr, sz).await.expect("Unexpcted error")
    );
}

#[async_std::test]
async fn read_across_1() {
    let addr = 0x3ba3_0ff6u64;
    let key = addr & PADDR_KEY;
    let key2 = key + PHYSICAL_PAGE_SZ as u64;
    let offset = addr & PADDR_OFFSET;
    let sz = 16;
    let split_sz = 10;

    let mut dom = MockDomain::default();

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];

            let offset = offset as usize;
            for (i, elt) in v.iter_mut().enumerate().skip(offset) {
                *elt = (i - offset + 1) as u8;
            }
            Ok(v)
        });

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key2);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key2, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];

            for (i, elt) in v.iter_mut().enumerate().take(sz - split_sz) {
                *elt = (i + split_sz + 1) as u8;
            }
            Ok(v)
        });

    let mut expect = vec![0u8; sz];
    for (i, elt) in expect.iter_mut().enumerate() {
        *elt = (i + 1) as u8;
    }
    let p_space = KVMIPhysical::new(dom);
    assert_eq!(
        expect,
        p_space.read(addr, sz).await.expect("Unexpcted error")
    );
}

#[async_std::test]
async fn read_across_2() {
    let addr = 0x3ba3_0ff6u64;
    let key = addr & PADDR_KEY;
    let key2 = key + PHYSICAL_PAGE_SZ as u64;
    let key3 = key + 2 * PHYSICAL_PAGE_SZ as u64;
    let offset = addr & PADDR_OFFSET;
    let sz = 16 + PHYSICAL_PAGE_SZ;
    let split_sz = 10;

    let mut dom = MockDomain::default();

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];

            let offset = offset as usize;
            for (i, elt) in v.iter_mut().enumerate().skip(offset) {
                *elt = (i - offset + 1) as u8;
            }
            Ok(v)
        });

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key2);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key2, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];
            for (i, elt) in v.iter_mut().enumerate() {
                *elt = (i + split_sz + 1) as u8;
            }
            Ok(v)
        });

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(key3);
    builder.set_read().set_execute();
    msg.push(builder.build());
    let mut seq = Sequence::new();
    dom.expect_send::<SetPageAccess>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(msg))
        .returning(|_| Ok(()));

    dom.expect_send::<ReadPhysical>()
        .once()
        .in_sequence(&mut seq)
        .with(eq(ReadPhysical::new(key3, PHYSICAL_PAGE_SZ as u64)))
        .returning(move |_| {
            let mut v = vec![0u8; PHYSICAL_PAGE_SZ];
            for (i, elt) in v
                .iter_mut()
                .enumerate()
                .take(sz - split_sz - PHYSICAL_PAGE_SZ)
            {
                *elt = (i + split_sz + PHYSICAL_PAGE_SZ + 1) as u8;
            }
            Ok(v)
        });

    let mut expect = vec![0u8; sz];
    for (i, elt) in expect.iter_mut().enumerate() {
        *elt = (i + 1) as u8;
    }
    let p_space = KVMIPhysical::new(dom);
    assert_eq!(
        expect,
        p_space.read(addr, sz).await.expect("Unexpcted error")
    );
}
