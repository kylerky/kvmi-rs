use kvmi_semantic::event::*;
use kvmi_semantic::memory::{self, handle_table};
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error};

use crate::kvmi_capnp::event;
use crate::kvmi_capnp::FileAccess;

use futures::future::{BoxFuture, FutureExt};

use log::error;

use async_std::sync::Sender;

use crate::collect::LogChT;

const FILE_INFORMATION_CLASS: &str = "_FILE_INFORMATION_CLASS";
const DISPOSITION_INFO: &str = "FileDispositionInformation";
const DISPOSITION_INFO_EX: &str = "FileDispositionInformationEx";

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

    let arch = &event.get_arch();
    let sregs = &arch.sregs;
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let regs = &arch.regs;
    let args = MSx64::new(&v_space, regs, 5).await?;

    let file_info_class = *args.get(4).unwrap();
    let file_handle = *args.get(0).unwrap();

    let res = if file_info_class == dispos || file_info_class == dispos_ex {
        handle_rm(dom, event, extra, log_tx, enable_ss, orig, file_handle).await
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
