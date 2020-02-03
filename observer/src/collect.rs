mod bp_handlers;

use std::collections::HashMap;
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
use kvmi_semantic::{Action, Domain, Error, HSToWire, RekallProfile};

use capnp::message::HeapAllocator;

use futures::future::BoxFuture;

const CPL_MASK: u16 = 3;
const TCPIP_SYS: &str = "tcpip.sys";

type BPHandler = Box<
    dyn for<'a> Fn(
            &'a mut Domain,
            &'a Event,
            &'a KvmiEventBreakpoint,
            &'a Sender<LogChT>,
            bool,
            u8,
        ) -> BoxFuture<'a, Result<(), Error>>
        + Sync
        + Send,
>;

struct EventHandler<'a> {
    dom: &'a mut Domain,
    log_tx: Sender<LogChT>,
    bps: HashMap<PhysicalAddrT, (u8, BPHandler)>,
    vcpu_gpa: HashMap<u16, PhysicalAddrT>,
}
impl<'a> EventHandler<'a> {
    fn new(dom: &'a mut Domain, log_tx: Sender<LogChT>) -> Self {
        EventHandler {
            dom,
            log_tx,
            bps: HashMap::new(),
            vcpu_gpa: HashMap::new(),
        }
    }

    async fn handle_event(&mut self, event: Event) -> Result<(), Error> {
        use EventExtra::*;

        let extra = event.get_extra();
        debug!("handle_evnt event: {:#?}", event.get_extra());
        match extra {
            PauseVCPU => handle_pause(self, &event).await?,
            Breakpoint(bp) => handle_bp(self, &event, bp, true).await?,
            SingleStep(ss) => handle_ss(self, &event, ss, true).await?,
            PF(pf) => handle_pf(self, &event, pf).await?,
            _ => debug!("Received event: {:?}", event),
        }
        Ok(())
    }

    async fn set_bp_by_physical(
        &mut self,
        gpa: PhysicalAddrT,
        handler: BPHandler,
    ) -> Result<(), Error> {
        let dom = &self.dom;
        let p_space = dom.get_k_vspace().get_base();
        let orig = p_space.read(gpa, 1).await?[0];
        dom.set_bp_by_physical(gpa).await?;
        self.bps.insert(gpa, (orig, handler));
        Ok(())
    }

    async fn drain_bps(&mut self) -> Result<(), Error> {
        let dom = &self.dom;
        for (gpa, (orig, _)) in self.bps.drain() {
            dom.clear_bp_by_physical(gpa, orig).await?;
        }
        Ok(())
    }
}
impl<'a> Drop for EventHandler<'a> {
    fn drop(&mut self) {
        if let Err(e) = task::block_on(shutdown(self)) {
            error!("Error shutting down: {}", e);
        }
    }
}

pub(crate) type LogChT = capnp::message::Builder<HeapAllocator>;
pub async fn listen(
    addr: PathBuf,
    profile: RekallProfile,
    tcpip_profile: RekallProfile,
    log_tx: Sender<LogChT>,
) -> Result<(), io::Error> {
    let listener = UnixListener::bind(&addr).await?;
    info!("Listening for KVMI connection");

    fs::set_permissions(&addr, Permissions::from_mode(0o666))?;
    if let Some(stream) = listener.incoming().next().await {
        info!("Accepted a new connection");
        let stream = stream?;

        let mut dom = Domain::new(
            stream,
            |_, _, _| Some(HSToWire::new()),
            profile,
            tcpip_profile,
            None,
        )
        .await?;

        dom.pause_vm().await?;
        let event_rx = dom.get_event_stream().clone();
        let mut handler = EventHandler::new(&mut dom, log_tx);
        while let Some(event) = event_rx.recv().await {
            handler.handle_event(event).await?;
        }
    }
    Ok(())
}

async fn handle_pause(handler: &mut EventHandler<'_>, event: &Event) -> Result<(), Error> {
    use Action::*;
    use EventKind::*;

    if handler.bps.is_empty() {
        let mut kernel_fns: Vec<(&str, BPHandler)> =
            vec![("NtOpenFile", Box::new(bp_handlers::open_file))];
        let mut tcp_fns = vec![];

        let dom = &handler.dom;
        let vcpu = event.get_vcpu();
        dom.toggle_event(vcpu, Breakpoint, true).await?;
        dom.toggle_event(vcpu, SingleStep, true).await?;
        dom.toggle_event(vcpu, PF, true).await?;

        let tcpip_base = dom.find_module(TCPIP_SYS).await?;
        debug!("tcpip.sys base: 0x{:x?}", tcpip_base);

        let bps = bp_handlers::get_bps(
            dom.get_kernel_base_va(),
            tcpip_base,
            kernel_fns.drain(..),
            tcp_fns.drain(..),
            dom.get_profile(),
            dom.get_tcpip_profile(),
        )
        .collect::<Result<Vec<(IA32eAddrT, BPHandler)>, Error>>()?;
        for (v_addr, func) in bps {
            let v_space = handler.dom.get_k_vspace();
            let gpa = v_space.lookup(v_addr).await?.ok_or(Error::InvalidVAddr)?;
            handler.set_bp_by_physical(gpa, func).await?;
        }
        debug!("bps: {:#x?}", handler.bps.keys());
    }

    handler.dom.reply(event, Continue).await?;
    Ok(())
}

async fn handle_bp(
    handler: &mut EventHandler<'_>,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    enable_ss: bool,
) -> Result<(), Error> {
    let dom = &mut handler.dom;
    debug!("handle_bp: gpa: 0x{:x?}", extra.get_gpa());
    let (orig, bp_handler) = match handler.bps.get(&extra.get_gpa()) {
        None => {
            dom.reply(event, Action::Continue).await?;
            return Ok(());
        }
        Some((orig, bp_handler)) => (*orig, bp_handler),
    };

    let sregs = &event.get_arch().sregs;
    let cs_sel = sregs.cs.selector;
    // current privilege level
    let cpl = cs_sel & CPL_MASK;

    if cpl != 0 {
        dom.resume_from_bp(orig, event, extra, enable_ss).await?;
        return Err(Error::Unsupported(String::from(
            "Handling break points not in ring 0 is not supported",
        )));
    }

    handler.vcpu_gpa.insert(event.get_vcpu(), extra.get_gpa());
    bp_handler(dom, event, extra, &handler.log_tx, enable_ss, orig).await
}

async fn handle_ss(
    handler: &mut EventHandler<'_>,
    event: &Event,
    _ss: &KvmiEventSingleStep,
    restore: bool,
) -> Result<(), Error> {
    use Action::*;

    let dom = &handler.dom;
    let vcpu = event.get_vcpu();
    let gpa = handler.vcpu_gpa.remove(&vcpu);
    if restore {
        if let Some(gpa) = gpa {
            // reset the breakpoint
            dom.set_bp_by_physical(gpa).await?;
        }
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

    info!("cleaning up");
    if let Err(e) = handler.drain_bps().await {
        error!("Error clearing bp: {}", e);
    }

    let dom = &mut handler.dom;
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
