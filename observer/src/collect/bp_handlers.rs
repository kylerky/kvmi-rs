pub(super) mod file;
pub(super) mod tcp;

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::memory;
use kvmi_semantic::{Error, RekallProfile};

use crate::kvmi_capnp::event;

use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use std::time::SystemTime;

use super::BPHandler;
use super::UnixDomain;

async fn get_process_by<T: AsRawFd>(
    v_space: &IA32eVirtual<T>,
    process: IA32eAddrT,
    profile: &RekallProfile,
) -> Result<(u64, u64, String), Error> {
    let pid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let pid = v_space.read(process + pid_rva, 8).await?;
    let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());

    let ppid_rva = profile.get_struct_field_offset("_EPROCESS", "InheritedFromUniqueProcessId")?;
    let ppid = v_space.read(process + ppid_rva, 8).await?;
    let ppid = u64::from_ne_bytes(ppid[..].try_into().unwrap());

    let image_file_ptr_rva = profile.get_struct_field_offset("_EPROCESS", "ImageFilePointer")?;
    let image_file_ptr = v_space.read(process + image_file_ptr_rva, 8).await?;
    let image_file_ptr = IA32eAddrT::from_ne_bytes(image_file_ptr[..].try_into().unwrap());

    let proc_file = if image_file_ptr != 0 {
        let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
        memory::read_utf16(&v_space, image_file_ptr + name_rva).await?
    } else {
        String::new()
    };

    Ok((pid, ppid, proc_file))
}

async fn get_process(
    dom: &mut UnixDomain,
    event: &Event,
    _sregs: &kvm_sregs,
) -> Result<(IA32eAddrT, u64, u64, String), Error> {
    let v_space = dom.get_k_vspace();
    let profile = dom.get_profile();

    let process = dom.get_current_process(event).await?;

    let pid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let pid = v_space.read(process + pid_rva, 8).await?;
    let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());

    let ppid_rva = profile.get_struct_field_offset("_EPROCESS", "InheritedFromUniqueProcessId")?;
    let ppid = v_space.read(process + ppid_rva, 8).await?;
    let ppid = u64::from_ne_bytes(ppid[..].try_into().unwrap());

    let image_file_ptr_rva = profile.get_struct_field_offset("_EPROCESS", "ImageFilePointer")?;
    let image_file_ptr = v_space.read(process + image_file_ptr_rva, 8).await?;
    let image_file_ptr = IA32eAddrT::from_ne_bytes(image_file_ptr[..].try_into().unwrap());

    let proc_file = if image_file_ptr != 0 {
        let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
        memory::read_utf16(&v_space, image_file_ptr + name_rva).await?
    } else {
        String::new()
    };

    Ok((process, pid, ppid, proc_file))
}

fn set_msg_proc(mut event_log: event::Builder, pid: u64, ppid: u64, proc_file: &str) {
    event_log.set_pid(pid);
    event_log.set_ppid(ppid);
    event_log.set_proc_file(proc_file);
    event_log.set_time_stamp(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64,
    );
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
