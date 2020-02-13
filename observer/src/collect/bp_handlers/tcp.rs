use kvmi_semantic::event::*;
use kvmi_semantic::memory::address_space::*;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error};

use crate::kvmi_capnp::event;
use crate::kvmi_capnp::TcpAccess;

use std::convert::TryInto;
use std::net::Ipv4Addr;

use async_std::sync::Sender;

use futures::future::{BoxFuture, FutureExt};

use log::error;

use crate::collect::{BPAction, LogChT};

pub(crate) fn tcp_receive<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<BPAction, Error>> {
    tcp_receive_(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn tcp_receive_(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<BPAction, Error> {
    let sregs = &event.get_arch().sregs;
    let (_, pid, proc_name) = super::get_process(dom, event, sregs).await?;

    let regs = &event.get_arch().regs;
    let v_space = dom.get_k_vspace();

    let addr = match get_ip(v_space, regs).await {
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, enable_ss).await {
                error!("Error resuming from bp: {}", err)
            }
            return Err(e);
        }
        Ok(ip) => ip,
    };
    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, &proc_name);

        let detail = event_log.get_detail();
        let mut tcp = detail.init_tcp();
        tcp.set_address(&format!("{}", addr));
        tcp.set_access(TcpAccess::Connect);
    }

    log_tx.send(message).await;
    Ok(BPAction::None)
}

async fn get_ip(v_space: &IA32eVirtual, regs: &kvm_regs) -> Result<Ipv4Addr, Error> {
    let args = MSx64::new(&v_space, regs, 1).await?;

    let p_tcp_end = args.get(0).unwrap();

    let p_addr_info = v_space
        .read(p_tcp_end + 0x18, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let p_addr_info = u64::from_ne_bytes(p_addr_info[..].try_into().unwrap());

    let p_remote_ip = v_space
        .read(p_addr_info + 0x10, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let p_remote_ip = u64::from_ne_bytes(p_remote_ip[..].try_into().unwrap());

    let remote_ip = v_space
        .read(p_remote_ip, 4)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let remote_ip: [u8; 4] = remote_ip[..].try_into().unwrap();
    let addr = Ipv4Addr::from(remote_ip);

    Ok(addr)
}
