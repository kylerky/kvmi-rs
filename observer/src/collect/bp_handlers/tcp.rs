use kvmi_semantic::event::*;
use kvmi_semantic::memory::address_space::*;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::Error;

use crate::kvmi_capnp::event;
use crate::kvmi_capnp::TcpAccess;

use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;

use async_std::sync::Sender;

use futures::future::{BoxFuture, FutureExt};

use log::error;

use crate::collect::{LogChT, UnixDomain};

pub(crate) fn send<'a>(
    dom: &'a mut UnixDomain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    handle_tcp(dom, event, extra, log_tx, enable_ss, orig, TcpAccess::Send).boxed()
}

pub(crate) fn recv<'a>(
    dom: &'a mut UnixDomain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    handle_tcp(dom, event, extra, log_tx, enable_ss, orig, TcpAccess::Recv).boxed()
}

async fn handle_tcp(
    dom: &mut UnixDomain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    access: TcpAccess,
) -> Result<(), Error> {
    match handle_tcp_(dom, event, extra, log_tx, enable_ss, orig, access).await {
        Ok(()) => Ok(()),
        Err(Error::InvalidVAddr) => dom.resume_from_bp(orig, event, extra, enable_ss).await,
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, enable_ss).await {
                error!("Error resuming from bp: {}", err);
            }
            Err(e)
        }
    }
}

async fn handle_tcp_(
    dom: &mut UnixDomain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    access: TcpAccess,
) -> Result<(), Error> {
    let v_space = dom.get_k_vspace();

    let regs = &event.get_arch().regs;
    let args = MSx64::new(&v_space, regs, 1).await?;
    let p_tcp_end = args.get(0).unwrap();
    let process = v_space.read(p_tcp_end + 0x290, 8).await?;
    let process = IA32eAddrT::from_ne_bytes(process[..8].try_into().unwrap());
    let (pid, ppid, proc_name) = super::get_process_by(v_space, process, dom.get_profile()).await?;

    let regs = &event.get_arch().regs;

    let addr = get_ip(&v_space, regs).await?;
    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, ppid, &proc_name);

        let detail = event_log.get_detail();
        let mut tcp = detail.init_tcp();
        tcp.set_address(&format!("{}", addr));
        tcp.set_access(access);
    }

    log_tx.send(message).await;
    Ok(())
}

async fn get_ip<T: AsRawFd>(v_space: &IA32eVirtual<T>, regs: &kvm_regs) -> Result<Ipv4Addr, Error> {
    let args = MSx64::new(&v_space, regs, 1).await?;

    let p_tcp_end = args.get(0).unwrap();

    let p_addr_info = v_space.read(p_tcp_end + 0x18, 8).await?;
    let p_addr_info = u64::from_ne_bytes(p_addr_info[..].try_into().unwrap());

    let p_remote_ip = v_space.read(p_addr_info + 0x10, 8).await?;
    let p_remote_ip = u64::from_ne_bytes(p_remote_ip[..].try_into().unwrap());

    let remote_ip = v_space.read(p_remote_ip, 4).await?;
    let remote_ip: [u8; 4] = remote_ip[..].try_into().unwrap();
    let addr = Ipv4Addr::from(remote_ip);

    Ok(addr)
}
