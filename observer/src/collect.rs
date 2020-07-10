mod bp_handlers;
use bp_handlers::{file, tcp};

use std::collections::HashMap;
use std::fs::{self, Permissions};
use std::io;
use std::mem;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use async_std::sync::{Receiver, Sender};

use smol::Async;

use log::{debug, error, info};

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::{Action, Domain, Error, HSToWire, RekallProfile};

use capnp::message::HeapAllocator;

use futures::future::BoxFuture;
use futures::select;
use futures::stream::StreamExt;

const CPL_MASK: u16 = 3;
const TCPIP_SYS: &str = "tcpip.sys";

type UnixDomain = Domain<UnixStream>;

type BPHandler = Box<
    dyn for<'a> Fn(
            &'a mut UnixDomain,
            &'a Event,
            &'a KvmiEventBreakpoint,
            &'a Sender<LogChT>,
            bool,
            u8,
        ) -> BoxFuture<'a, Result<(), Error>>
        + Sync
        + Send,
>;

struct EventHandler {
    dom: UnixDomain,
    log_tx: Sender<LogChT>,
    bps: HashMap<PhysicalAddrT, (u8, BPHandler)>,
    vcpu_gpa: HashMap<u16, PhysicalAddrT>,
}
impl EventHandler {
    fn new(dom: UnixDomain, log_tx: Sender<LogChT>) -> Self {
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

pub(crate) type LogChT = capnp::message::Builder<HeapAllocator>;
pub async fn listen(
    addr: PathBuf,
    profile: RekallProfile,
    tcpip_profile: RekallProfile,
    log_tx: Sender<LogChT>,
    close: Receiver<()>,
) -> Result<(), io::Error> {
    let listener = Async::<UnixListener>::bind(&addr)?;
    info!("Listening for KVMI connection");

    fs::set_permissions(&addr, Permissions::from_mode(0o666))?;
    let mut close = close.fuse();
    let mut incoming = listener.incoming().fuse();
    let (event_rx, mut handler, join_handle) = select! {
        _ = close.next() => return Ok(()),
        res = incoming.next() => {
            match res {
                None => return Ok(()),
                Some(stream) => {
                    info!("Accepted a new connection");
                    let stream = stream?;

                    let (dom, handle) = UnixDomain::new(
                        stream,
                        |_, _, _| Some(HSToWire::new()),
                        profile,
                        tcpip_profile,
                        None,
                    )
                    .await?;

                    dom.pause_vm().await?;
                    let event_rx = dom.get_event_stream().clone();
                    let handler = EventHandler::new(dom, log_tx);
                    (event_rx, handler, handle)
                }
            }
        }
    };
    let mut event_rx = event_rx.fuse();
    loop {
        select! {
            res = event_rx.next() => {
                match res {
                    None => return Ok(()),
                    Some(event) => {
                        handler.handle_event(event).await?
                    }
                }
            }
            _ = close.next() => {
                let res = async_std::io::timeout(Duration::from_secs(5), async {
                    shutdown(&mut handler).await.map_err(|e| e.into())
                })
                .await;
                mem::drop(handler);
                join_handle.await;
                return res;
            },
        }
    }
}

async fn handle_pause(handler: &mut EventHandler, event: &Event) -> Result<(), Error> {
    use Action::*;
    use EventKind::*;

    let dom = &handler.dom;
    let vcpu = event.get_vcpu();
    dom.toggle_event(vcpu, Breakpoint, true).await?;
    dom.toggle_event(vcpu, SingleStep, true).await?;
    dom.toggle_event(vcpu, PF, true).await?;

    if handler.bps.is_empty() {
        let mut kernel_fns: Vec<(&str, BPHandler)> = vec![
            ("NtWriteFile", Box::new(file::write)),
            ("NtReadFile", Box::new(file::read)),
            ("NtSetInformationFile", Box::new(file::set_info)),
        ];
        let mut tcp_fns: Vec<(&str, BPHandler)> = vec![
            ("TcpTcbSend", Box::new(tcp::send)),
            ("TcpDeliverReceive", Box::new(tcp::recv)),
        ];

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
            let gpa = v_space.lookup(v_addr).await?;
            handler.set_bp_by_physical(gpa, func).await?;
        }
        debug!("bps: {:#x?}", handler.bps.keys());
    }

    handler.dom.reply(event, Continue).await?;
    debug!("continued");
    Ok(())
}

async fn handle_bp(
    handler: &mut EventHandler,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    enable_ss: bool,
) -> Result<(), Error> {
    let dom = &mut handler.dom;
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
    handler: &mut EventHandler,
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
    handler: &EventHandler,
    event: &Event,
    extra: &KvmiEventPF,
) -> Result<(), Error> {
    let dom = &handler.dom;
    dom.handle_pf(event, extra).await
}

async fn shutdown(handler: &mut EventHandler) -> Result<(), Error> {
    use EventExtra::*;

    info!("cleaning up");
    if let Err(e) = handler.drain_bps().await {
        error!("Error clearing bp: {}", e);
    }
    debug!("breakpoitns cleared");

    let dom = &mut handler.dom;
    let vcpu_num = dom.get_vcpu_num().await? as usize;
    for vcpu in 0..vcpu_num as u16 {
        dom.toggle_event(vcpu, EventKind::Breakpoint, false).await?;
        dom.toggle_event(vcpu, EventKind::SingleStep, false).await?;
        dom.toggle_event(vcpu, EventKind::PF, false).await?;
    }
    debug!("unsubscribed");

    let event_rx = dom.get_event_stream().clone();
    while !event_rx.is_empty() {
        if let Ok(event) = event_rx.recv().await {
            let extra = event.get_extra();
            match extra {
                Breakpoint(bp) => handle_bp(handler, &event, bp, false).await?,
                SingleStep(ss) => handle_ss(handler, &event, ss, false).await?,
                PF(pf) => handle_pf(handler, &event, pf).await?,
                _ => debug!("Received event: {:?}", event),
            }
        }
    }
    debug!("events drained");
    Ok(())
}
