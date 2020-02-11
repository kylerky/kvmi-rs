use kvmi_semantic::event::*;
use kvmi_semantic::memory::address_space::*;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error};

use std::convert::TryInto;

use async_std::sync::Sender;

use futures::future::{BoxFuture, FutureExt};

use crate::collect::LogChT;

use log::debug;

pub fn tcp_receive<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    _tcp_receive(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn _tcp_receive(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    let sregs = &event.get_arch().sregs;
    let (process, pid, proc_name) = super::get_process(dom, event, sregs).await?;

    let regs = &event.get_arch().regs;
    let v_space = dom.get_k_vspace();

    let res = get_ip(v_space, regs).await;
    let res2 = dom.resume_from_bp(orig, event, extra, enable_ss).await;

    res.and(res2)
}

async fn get_ip(v_space: &IA32eVirtual, regs: &kvm_regs) -> Result<(), Error> {
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
    debug!("remote ip: {:?}", remote_ip);

    Ok(())
}
