mod file;
pub(crate) use file::*;

mod tcp;
pub(crate) use tcp::*;

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::{Domain, Error, RekallProfile};

use crate::kvmi_capnp::event;

use std::convert::TryInto;

use super::BPHandler;

async fn get_process(
    dom: &mut Domain,
    event: &Event,
    sregs: &kvm_sregs,
) -> Result<(IA32eAddrT, u64, u64, String), Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let arch = event.get_arch();
    let process = dom.get_current_process(&arch.sregs).await?;

    let pid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let pid = v_space.read(process + pid_rva, 8).await?;
    let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());

    let ppid_rva = profile.get_struct_field_offset("_EPROCESS", "InheritedFromUniqueProcessId")?;
    let ppid = v_space.read(process + ppid_rva, 8).await?;
    let ppid = u64::from_ne_bytes(ppid[..].try_into().unwrap());

    let image_name_rva = profile.get_struct_field_offset("_EPROCESS", "ImageFileName")?;
    let image_name = v_space.read(process + image_name_rva, 15).await?;
    let name_len = image_name
        .iter()
        .position(|&c| c == b'\0')
        .unwrap_or_else(|| image_name.len());
    let proc_name = String::from_utf8(image_name[..name_len].to_vec())?;

    Ok((process, pid, ppid, proc_name))
}

fn set_msg_proc(mut event_log: event::Builder, pid: u64, ppid: u64, proc_name: &str) {
    event_log.set_pid(pid);
    event_log.set_ppid(ppid);
    event_log.set_proc_name(proc_name);
}

type OutputItem = Result<(IA32eAddrT, BPHandler), Error>;
type InputItem = (&'static str, BPHandler);

pub(crate) fn get_bps<'a, T, O>(
    kernel_base_va: IA32eAddrT,
    tcpip_base: IA32eAddrT,
    kernel_fns: T,
    tcp_fns: O,
    profile: &'a RekallProfile,
    tcpip_profile: &'a RekallProfile,
) -> impl Iterator<Item = OutputItem> + 'a
where
    T: IntoIterator<Item = InputItem> + 'a,
    O: IntoIterator<Item = InputItem> + 'a,
{
    let kfuncs = kernel_fns
        .into_iter()
        .map(move |(symbol, handler)| -> OutputItem {
            let v_addr = kernel_base_va + profile.get_func_offset(symbol)?;
            Ok((v_addr, handler))
        });
    let tfuncs = tcp_fns
        .into_iter()
        .map(move |(symbol, handler)| -> OutputItem {
            let v_addr = tcpip_base + tcpip_profile.get_func_offset(symbol)?;
            Ok((v_addr, handler))
        });
    kfuncs.chain(tfuncs)
}
