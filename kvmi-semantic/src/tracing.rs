pub mod functions;

use crate::event::*;
use crate::memory::address_space::{IA32eVirtual, KVMIPhysical, PhysicalAddrT};
use crate::Action;
use crate::{Error, Result};

use kvmi::message::{CommonEventReply, ControlSingleStep};

use std::os::unix::io::AsRawFd;

const BP_INSTRUCTION: u8 = 0xcc;

pub(super) async fn resume_from_bp<T: AsRawFd>(
    v_space: &IA32eVirtual<T>,
    orig: u8,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    enable_ss: bool,
) -> Result<()> {
    use Action::*;

    let insn_len = extra.get_insn_len();
    if insn_len != 1 {
        return Err(Error::Unsupported(String::from(
            "Unsupported encoding of the breakpoint instruction",
        )));
    }

    // clear the breakpoint
    let gpa = extra.get_gpa();
    let p_space = v_space.get_base();
    p_space.write(gpa, vec![orig]).await?;

    // let the VM continue, possibly in single step mode
    let dom = p_space.get_dom();
    if enable_ss {
        let vcpu = event.get_vcpu();
        dom.send(ControlSingleStep::new(vcpu, true)).await?;
    }
    let bp_reply = CommonEventReply::new(event, Retry).ok_or(Error::WrongEvent)?;
    dom.send(bp_reply).await?;
    Ok(())
}

pub(super) async fn set_bp_by_physical<T: AsRawFd>(
    p_space: &KVMIPhysical<T>,
    addr: PhysicalAddrT,
) -> Result<()> {
    p_space.write(addr, vec![BP_INSTRUCTION]).await?;
    Ok(())
}
