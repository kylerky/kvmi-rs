use std::convert::TryInto;
use std::fs::{self, Permissions};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use async_std::os::unix::net::UnixListener;
use async_std::prelude::*;
use async_std::sync::Sender;
use async_std::task;

use log::{debug, error, info};

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::memory;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Action, Domain, Error, HSToWire, RekallProfile};

use crate::kvmi_capnp::event;

use capnp::message::HeapAllocator;

const CPL_MASK: u16 = 3;

struct EventHandler<'a> {
    dom: &'a mut Domain,
    orig_byte: u8,
    gpa: PhysicalAddrT,
    log_tx: Sender<LogChT>,
    bp_set: bool,
}
impl<'a> EventHandler<'a> {
    fn new(dom: &'a mut Domain, orig_byte: u8, gpa: PhysicalAddrT, log_tx: Sender<LogChT>) -> Self {
        EventHandler {
            dom,
            orig_byte,
            gpa,
            log_tx,
            bp_set: false,
        }
    }

    async fn handle_event(&mut self, event: Event) -> Result<(), Error> {
        use EventExtra::*;

        let extra = event.get_extra();
        match extra {
            PauseVCPU => handle_pause(self, &event).await?,
            Breakpoint(bp) => handle_bp(self, &event, bp, true).await?,
            SingleStep(ss) => handle_ss(self, &event, ss, true).await?,
            PF(pf) => handle_pf(self, &event, pf).await?,
            _ => debug!("Received event: {:?}", event),
        }
        Ok(())
    }
}
impl<'a> Drop for EventHandler<'a> {
    fn drop(&mut self) {
        if self.bp_set {
            if let Err(e) = task::block_on(shutdown(self)) {
                error!("Error shutting down: {}", e);
            }
        }
    }
}

pub(crate) type LogChT = capnp::message::Builder<HeapAllocator>;
pub async fn listen(
    addr: PathBuf,
    profile: RekallProfile,
    log_tx: Sender<LogChT>,
) -> Result<(), io::Error> {
    let listener = UnixListener::bind(&addr).await?;
    info!("Listening for KVMI connection");

    fs::set_permissions(&addr, Permissions::from_mode(0o666))?;
    if let Some(stream) = listener.incoming().next().await {
        info!("Accepted a new connection");
        let stream = stream?;

        let mut dom = Domain::new(stream, |_, _, _| Some(HSToWire::new()), profile, None).await?;

        let profile = dom.get_profile();
        let v_addr = dom.get_kernel_base_va() + profile.get_kfunc_offset("NtOpenFile")?;
        let v_space = dom.get_k_vspace();
        let p_space = v_space.get_base();
        let gpa = v_space.lookup(v_addr).await?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Cannot translate address of NtOpenFile",
            )
        })?;

        dom.pause_vm().await?;

        let orig = p_space.read(gpa, 1).await?[0];

        let event_rx = dom.get_event_stream().clone();
        let mut handler = EventHandler::new(&mut dom, orig, gpa, log_tx);
        while let Some(event) = event_rx.recv().await {
            handler.handle_event(event).await?;
        }
    }
    Ok(())
}

async fn handle_pause(handler: &mut EventHandler<'_>, event: &Event) -> Result<(), Error> {
    use Action::*;
    use EventKind::*;

    let dom = &handler.dom;
    let gpa = handler.gpa;
    let bp_set = &mut handler.bp_set;

    let vcpu = event.get_vcpu();
    dom.toggle_event(vcpu, Breakpoint, true).await?;
    dom.toggle_event(vcpu, SingleStep, true).await?;
    dom.toggle_event(vcpu, PF, true).await?;

    if !*bp_set {
        debug!("bp address: {:x?}", gpa);
        *bp_set = true;
        dom.set_bp_by_physical(gpa).await?;
    }

    dom.reply(event, Continue).await?;
    Ok(())
}

async fn handle_bp(
    handler: &mut EventHandler<'_>,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    enable_ss: bool,
) -> Result<(), Error> {
    let dom = &mut handler.dom;
    let gpa = handler.gpa;
    let orig = handler.orig_byte;
    let log_tx = &handler.log_tx;
    if extra.get_gpa() != gpa {
        dom.reply(event, Action::Continue).await?;
        return Ok(());
    }

    let sregs = &event.get_arch().sregs;
    let cs_sel = sregs.cs.selector;
    // current privilege level
    let cpl = cs_sel & CPL_MASK;

    if cpl != 0 {
        dom.resume_from_bp(orig, event, extra, enable_ss).await?;
        return Err(Error::Unsupported(String::from(
            "Reading process info not in ring 0 is not supported",
        )));
    }

    let pid = get_pid(dom, event, sregs).await?;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        event_log.set_pid(pid);
    }
    log_tx.send(message).await;

    match get_file_info(dom, event, sregs).await {
        Ok(_) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, false).await {
                error!("Error resuming from bp: {}", err);
            }
            Err(e)
        }
    }
}

async fn get_pid(dom: &mut Domain, event: &Event, sregs: &kvm_sregs) -> Result<u64, Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let uid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let arch = event.get_arch();
    let process = dom.get_current_process(&arch.sregs).await?;
    let pid = v_space
        .read(process + uid_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
    Ok(pid)
}

async fn get_file_info(dom: &mut Domain, event: &Event, sregs: &kvm_sregs) -> Result<(), Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let regs = &event.get_arch().regs;
    let args = MSx64::new(&v_space, regs, 3).await?;
    let obj_attr_ptr = args.get(2).unwrap();
    if *obj_attr_ptr == 0 {
        return Ok(());
    }

    let fname_rva = profile.get_struct_field_offset("_OBJECT_ATTRIBUTES", "ObjectName")?;
    let fname_ptr = v_space
        .read(obj_attr_ptr + fname_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let fname_ptr = u64::from_ne_bytes(fname_ptr[..].try_into().unwrap());
    if fname_ptr == 0 || !IA32eVirtual::is_canonical(fname_ptr) {
        return Ok(());
    }
    let _fname = memory::read_utf16(&v_space, fname_ptr).await?;

    Ok(())
}

async fn handle_ss(
    handler: &EventHandler<'_>,
    event: &Event,
    _ss: &KvmiEventSingleStep,
    restore: bool,
) -> Result<(), Error> {
    use Action::*;

    let dom = &handler.dom;
    let gpa = handler.gpa;
    // reset the breakpoint
    if restore {
        dom.set_bp_by_physical(gpa).await?;
    }
    // quit single step mode
    dom.toggle_single_step(event.get_vcpu(), false).await?;
    dom.reply(event, Continue).await?;
    Ok(())
}

async fn handle_pf(
    handler: &EventHandler<'_>,
    event: &Event,
    extra: &KvmiEventPF,
) -> Result<(), Error> {
    let dom = &handler.dom;
    dom.handle_pf(event, extra).await
}

async fn shutdown(handler: &mut EventHandler<'_>) -> Result<(), Error> {
    use EventExtra::*;

    let dom = &mut handler.dom;
    let orig = handler.orig_byte;
    let gpa = handler.gpa;

    info!("cleaning up");
    clear_bp(dom, gpa, orig).await;

    let vcpu_num = dom.get_vcpu_num().await? as usize;
    for vcpu in 0..vcpu_num as u16 {
        dom.toggle_event(vcpu, EventKind::Breakpoint, false).await?;
        dom.toggle_event(vcpu, EventKind::SingleStep, false).await?;
        dom.toggle_event(vcpu, EventKind::PF, false).await?;
    }

    let event_rx = dom.get_event_stream().clone();
    while !event_rx.is_empty() {
        if let Some(event) = event_rx.recv().await {
            let extra = event.get_extra();
            match extra {
                Breakpoint(bp) => handle_bp(handler, &event, bp, false).await?,
                SingleStep(ss) => handle_ss(handler, &event, ss, false).await?,
                PF(pf) => handle_pf(handler, &event, pf).await?,
                _ => debug!("Received event: {:?}", event),
            }
        }
    }
    Ok(())
}

async fn clear_bp(dom: &Domain, gpa: PhysicalAddrT, orig: u8) {
    debug!("Clearing bp");
    let res = dom.clear_bp_by_physical(gpa, orig).await;
    if let Err(err) = res {
        error!("Error clearing bp: {}", err);
    }
}