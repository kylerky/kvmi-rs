use kvmi_semantic::event::*;
use kvmi_semantic::memory::address_space::{IA32eAddrT, IA32eVirtual};
use kvmi_semantic::memory::{self, handle_table};
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error, RekallProfile};

use crate::kvmi_capnp::event;
use crate::kvmi_capnp::FileAccess;

use futures::future::{BoxFuture, FutureExt};

use std::convert::TryInto;

use log::error;

use async_std::sync::Sender;

use crate::collect::LogChT;

const FILE_INFORMATION_CLASS: &str = "_FILE_INFORMATION_CLASS";
const DISPOSITION_INFO: &str = "FileDispositionInformation";
const DISPOSITION_INFO_EX: &str = "FileDispositionInformationEx";
const RENAME_INFO: &str = "FileRenameInformation";

struct SetInfoParams {
    file_handle: u64,
    file_info: IA32eAddrT,
}

pub(crate) fn read<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    read_file(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn read_file(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    handle_rw(dom, FileAccess::Read, event, extra, log_tx, enable_ss, orig).await
}

pub(crate) fn write<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    write_file(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn write_file(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    handle_rw(
        dom,
        FileAccess::Write,
        event,
        extra,
        log_tx,
        enable_ss,
        orig,
    )
    .await
}

async fn handle_rw(
    dom: &mut Domain,
    access: FileAccess,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    match handle_rw_(dom, access, event, extra, log_tx, enable_ss, orig).await {
        Ok(()) => Ok(()),
        Err(Error::InvalidVAddr) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(Error::FromUtf16(_)) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, enable_ss).await {
                error!("Error resuming from bp: {}", err);
            }
            Err(e)
        }
    }
}

async fn handle_rw_(
    dom: &mut Domain,
    access: FileAccess,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    let sregs = &event.get_arch().sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();

    let regs = &event.get_arch().regs;
    let args = MSx64::new(&v_space, regs, 1).await?;
    let handle = args.get(0).unwrap();

    let (process, pid, ppid, proc_name) = super::get_process(dom, event, sregs).await?;
    let profile = dom.get_profile();
    let file_obj_ptr = handle_table::get_obj_by(&v_space, *handle, process, profile).await?;

    let body_rva = profile.get_struct_field_offset("_OBJECT_HEADER", "Body")?;
    let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
    let fname = memory::read_utf16(&v_space, file_obj_ptr + body_rva + name_rva).await?;

    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, ppid, &proc_name);

        let detail = event_log.get_detail();
        let mut file = detail.init_file();
        file.set_name(&fname);
        file.set_access(access);
    }

    log_tx.send(message).await;
    Ok(())
}

pub(crate) fn set_info<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    set_info_(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn set_info_(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    let profile = dom.get_profile();
    let info_class = profile
        .rev_enums
        .get(FILE_INFORMATION_CLASS)
        .ok_or_else(|| Error::Profile(format!("Missing enum {}", FILE_INFORMATION_CLASS)))?;

    let dispos = *info_class.get(DISPOSITION_INFO).ok_or_else(|| {
        Error::Profile(format!(
            "Missing enum variant {}::{}",
            FILE_INFORMATION_CLASS, DISPOSITION_INFO,
        ))
    })? as u64;
    let dispos_ex = *info_class.get(DISPOSITION_INFO_EX).ok_or_else(|| {
        Error::Profile(format!(
            "Missing enum variant {}::{}",
            FILE_INFORMATION_CLASS, DISPOSITION_INFO_EX,
        ))
    })? as u64;
    let rename = *info_class.get(RENAME_INFO).ok_or_else(|| {
        Error::Profile(format!(
            "Missing enum variant {}::{}",
            FILE_INFORMATION_CLASS, RENAME_INFO,
        ))
    })? as u64;

    let arch = &event.get_arch();
    let sregs = &arch.sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let regs = &arch.regs;
    let args = MSx64::new(&v_space, regs, 5).await?;

    let file_info_class = *args.get(4).unwrap();
    let file_handle = *args.get(0).unwrap();

    let res = if file_info_class == dispos || file_info_class == dispos_ex {
        handle_rm(dom, event, extra, log_tx, enable_ss, orig, file_handle).await
    } else if file_info_class == rename {
        let file_info = *args.get(2).unwrap();
        let params = SetInfoParams {
            file_info,
            file_handle,
        };
        handle_mv(dom, event, extra, log_tx, enable_ss, orig, params).await
    } else {
        dom.resume_from_bp(orig, event, extra, enable_ss).await?;
        Ok(())
    };
    match res {
        Ok(()) => Ok(()),
        Err(Error::InvalidVAddr) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(Error::FromUtf16(_)) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, enable_ss).await {
                error!("Error resuming from bp: {}", err);
            }
            Err(e)
        }
    }
}

async fn handle_rm(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    file_handle: u64,
) -> Result<(), Error> {
    let sregs = &event.get_arch().sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();

    let (process, pid, ppid, proc_name) = super::get_process(dom, event, sregs).await?;
    let profile = dom.get_profile();
    let file_obj_ptr = handle_table::get_obj_by(&v_space, file_handle, process, profile).await?;

    let body_rva = profile.get_struct_field_offset("_OBJECT_HEADER", "Body")?;
    let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
    let fname = memory::read_utf16(&v_space, file_obj_ptr + body_rva + name_rva).await?;

    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, ppid, &proc_name);

        let detail = event_log.get_detail();
        let mut file = detail.init_file();
        file.set_name(&fname);
        file.set_access(FileAccess::Remove);
    }

    log_tx.send(message).await;
    Ok(())
}

async fn handle_mv(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
    params: SetInfoParams,
) -> Result<(), Error> {
    let sregs = &event.get_arch().sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();

    let (process, pid, ppid, proc_name) = super::get_process(dom, event, sregs).await?;
    let profile = dom.get_profile();
    let file_handle = params.file_handle;
    let file_obj_ptr = handle_table::get_obj_by(&v_space, file_handle, process, profile).await?;

    let body_rva = profile.get_struct_field_offset("_OBJECT_HEADER", "Body")?;
    let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
    let fname = memory::read_utf16(&v_space, file_obj_ptr + body_rva + name_rva).await?;

    let file_info = params.file_info;
    let name_len = v_space.read(file_info + 16, 4).await?;
    let name_len = u32::from_ne_bytes(name_len[..].try_into().unwrap()) as usize;

    let buffer = v_space.read(file_info + 16 + 4, name_len).await?;
    let buffer: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes(bytes.try_into().unwrap()))
        .collect();
    let mut new_name = String::from_utf16(&buffer[..])?;
    let new_root_dir_handle = v_space.read(file_info + 8, 8).await?;
    let new_root_dir_handle = u64::from_ne_bytes(new_root_dir_handle[..].try_into().unwrap());
    if new_root_dir_handle > 0 {
        let root_dir = get_root_dir(
            &v_space,
            process,
            new_root_dir_handle,
            profile,
            body_rva,
            name_rva,
        )
        .await?;
        new_name = format!(r"{}\{}", root_dir, new_name);
    } else if new_name.starts_with(r"\??\") {
        // full canonical path
        // remove prefixes like \??\C:
        let (_, rest) = new_name.split_at(r"\??\C:".len());
        new_name = String::from(rest);
    } else {
        let backslash = '\\';
        let mut fname2 = fname.clone();
        let slash_pos = fname2.rfind(backslash).ok_or(Error::InvalidVAddr)?;
        fname2.truncate(slash_pos + backslash.len_utf8());
        fname2.push_str(&new_name);
        new_name = fname2;
    }

    dom.resume_from_bp(orig, event, extra, enable_ss).await?;

    // a rename event is sent as
    // a read from the old file
    // and a write to the new file
    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, ppid, &proc_name);

        let detail = event_log.get_detail();
        let mut file = detail.init_file();
        file.set_name(&fname);
        file.set_access(FileAccess::Read);
    }

    log_tx.send(message).await;

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, ppid, &proc_name);

        let detail = event_log.get_detail();
        let mut file = detail.init_file();
        file.set_name(&new_name);
        file.set_access(FileAccess::Write);
    }

    log_tx.send(message).await;

    Ok(())
}

async fn get_root_dir(
    v_space: &IA32eVirtual,
    process: IA32eAddrT,
    handle: u64,
    profile: &RekallProfile,
    body_rva: u64,
    name_rva: u64,
) -> Result<String, Error> {
    let root_dir_ptr = handle_table::get_obj_by(v_space, handle, process, profile).await?;
    let dir_name = memory::read_utf16(&v_space, root_dir_ptr + body_rva + name_rva).await?;
    Ok(dir_name)
}
