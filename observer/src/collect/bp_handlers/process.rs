use kvmi_semantic::event::*;
use kvmi_semantic::memory::address_space::IA32eAddrT;
use kvmi_semantic::memory::handle_table;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error};

use futures::future::{BoxFuture, FutureExt};

use crate::kvmi_capnp::event;

use crate::collect::PTR_SZ;
use crate::collect::{BPAction, LogChT};

use async_std::sync::Sender;

use std::convert::TryInto;

use log::debug;

pub(crate) fn fork<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<BPAction, Error>> {
    fork_(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn fork_(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<BPAction, Error> {
    match fork_set_ret_trap(dom, event, extra, log_tx, enable_ss, orig).await {
        Ok(res) => Ok(res),
        Err(Error::InvalidVAddr) => Ok(BPAction::None),
        Err(e) => Err(e),
    }
}

async fn fork_set_ret_trap(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    _log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<BPAction, Error> {
    debug!("fork");
    let arch = event.get_arch();
    let sregs = &arch.sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();

    let regs = &arch.regs;
    let ret_addr = v_space.read(regs.rsp, PTR_SZ).await?;
    let ret_addr = IA32eAddrT::from_ne_bytes(ret_addr[..].try_into().unwrap());

    let gpa = v_space.lookup(ret_addr).await?;
    let p_space = v_space.get_base();
    let ret_orig = p_space.read(gpa, 1).await?[0];
    dom.set_bp_by_physical(gpa).await?;
    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    let args = MSx64::new(&v_space, regs, 1).await?;
    let proc_handle_ptr = *args.get(0).unwrap();
    Ok(BPAction::Add((
        gpa,
        (
            ret_orig,
            Box::new(move |dom, event, extra, log_tx, enable_ss, orig| {
                fork_ret(dom, event, extra, log_tx, enable_ss, orig, proc_handle_ptr)
            }),
        ),
    )))
}

pub(crate) fn fork_ret<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    proc_handle_ptr: IA32eAddrT,
) -> BoxFuture<'a, Result<BPAction, Error>> {
    fork_ret_(dom, event, extra, log_tx, enable_ss, orig, proc_handle_ptr).boxed()
}

async fn fork_ret_(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    proc_handle_ptr: IA32eAddrT,
) -> Result<BPAction, Error> {
    match fork_ret_get_new(dom, event, extra, log_tx, enable_ss, orig, proc_handle_ptr).await {
        Ok(()) | Err(Error::InvalidVAddr) => {
            let gpa = extra.get_gpa();
            Ok(BPAction::Remove(gpa))
        }
        Err(e) => Err(e),
    }
}

async fn fork_ret_get_new(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    proc_handle_ptr: IA32eAddrT,
) -> Result<(), Error> {
    debug!("fork ret");
    let sregs = &event.get_arch().sregs;
    let (process, pid, proc_name) = super::get_process(dom, event, sregs).await?;

    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let proc_handle = v_space.read(proc_handle_ptr, PTR_SZ).await?;
    let proc_handle = IA32eAddrT::from_ne_bytes(proc_handle[..].try_into().unwrap());

    let profile = dom.get_profile();
    let eprocess_obj_ptr =
        handle_table::get_obj_by(&v_space, proc_handle, process, profile).await?;

    let body_rva = profile.get_struct_field_offset("_OBJECT_HEADER", "Body")?;

    let process_ptr = eprocess_obj_ptr + body_rva;
    let image_name_rva = profile.get_struct_field_offset("_EPROCESS", "ImageFileName")?;
    let image_name = v_space.read(process_ptr + image_name_rva, 15).await?;
    let name_len = image_name
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or_else(|| image_name.len());
    let new_proc_name = String::from_utf8(image_name[..name_len].to_vec())?;

    let pid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let child_pid = v_space.read(process_ptr + pid_rva, 8).await?;
    let child_pid = u64::from_ne_bytes(child_pid[..].try_into().unwrap());

    dom.resume_from_bp(orig, event, extra, enable_ss).await?;
    debug!("new proc: {}", new_proc_name);

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, &proc_name);

        let detail = event_log.get_detail();
        let mut fork = detail.init_fork();
        fork.set_pid(child_pid);
        fork.set_proc_name(&new_proc_name);
    }

    log_tx.send(message).await;
    Ok(())
}
