use super::*;
use kvmi::message::GetRegistersReply;

use std::os::unix::net::UnixStream;

use pretty_assertions::assert_eq;

#[test]
fn get_paging_mode_none() {
    use PageMode::*;

    let mut reply = GetRegistersReply::default();
    unsafe {
        reply.get_regs_mut().sregs.cr0 = 0x7fa4_8d2f;
    }
    assert_eq!(Real, Domain::<UnixStream>::get_paging_mode_from(&reply));
}

#[test]
fn get_paging_mode_ia32e() {
    use PageMode::*;

    let mut reply = GetRegistersReply::default();
    unsafe {
        let sregs = &mut reply.get_regs_mut().sregs;
        sregs.cr0 = 0x8fa4_8d2f;
        sregs.cr4 = 0x20;
        sregs.efer = 0x100;
    }
    assert_eq!(IA32e, Domain::<UnixStream>::get_paging_mode_from(&reply));
}

#[test]
fn get_paging_mode_other() {
    use PageMode::*;

    let mut reply = GetRegistersReply::default();
    unsafe {
        let sregs = &mut reply.get_regs_mut().sregs;
        sregs.cr0 = 0x8fa4_8d2f;
        sregs.cr4 = 0x10;
    }
    assert_eq!(Other, Domain::<UnixStream>::get_paging_mode_from(&reply));
}
