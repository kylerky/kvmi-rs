use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::memory::{self, handle_table};
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Domain, Error, RekallProfile};

use crate::kvmi_capnp::event;
use crate::kvmi_capnp::Access;

use std::convert::TryInto;

use futures::future::{BoxFuture, FutureExt};

use log::{debug, error};

use async_std::sync::Sender;

use crate::collect::LogChT;

pub fn open_file<'a>(
    dom: &'a mut Domain,
    event: &'a Event,
    extra: &'a KvmiEventBreakpoint,
    log_tx: &'a Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> BoxFuture<'a, Result<(), Error>> {
    _open_file(dom, event, extra, log_tx, enable_ss, orig).boxed()
}

async fn _open_file(
    dom: &mut Domain,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    log_tx: &Sender<LogChT>,
    enable_ss: bool,
    orig: u8,
) -> Result<(), Error> {
    let sregs = &event.get_arch().sregs;
    let (process, pid, proc_name) = super::get_process(dom, event, sregs).await?;

    let fname = match get_file_info(dom, event, sregs, process).await {
        Ok(fname) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            fname
        }
        Err(Error::InvalidVAddr) => {
            debug!("Invalid virtual addr");
            return dom.resume_from_bp(orig, event, extra, enable_ss).await;
        }
        Err(Error::FromUtf8(_)) => {
            return dom.resume_from_bp(orig, event, extra, enable_ss).await;
        }
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, false).await {
                error!("Error resuming from bp: {}", err);
            }
            return Err(e);
        }
    };

    let mut message = capnp::message::Builder::new_default();
    {
        let mut event_log = message.init_root::<event::Builder>();
        super::set_msg_proc(event_log.reborrow(), pid, &proc_name);

        let detail = event_log.get_detail();
        let mut file = detail.init_file();
        file.set_name(&fname);
        file.set_access(Access::Open);
    }

    log_tx.send(message).await;
    Ok(())
}

async fn get_file_info(
    dom: &mut Domain,
    event: &Event,
    sregs: &kvm_sregs,
    process: IA32eAddrT,
) -> Result<String, Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let regs = &event.get_arch().regs;
    let args = MSx64::new(&v_space, regs, 3).await?;
    let obj_attr_ptr = args.get(2).unwrap();
    if *obj_attr_ptr == 0 {
        return Err(Error::InvalidVAddr);
    }

    let fname_rva = profile.get_struct_field_offset("_OBJECT_ATTRIBUTES", "ObjectName")?;
    let fname_ptr = v_space
        .read(obj_attr_ptr + fname_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let fname_ptr = u64::from_ne_bytes(fname_ptr[..].try_into().unwrap());
    if fname_ptr == 0 || !IA32eVirtual::is_canonical(fname_ptr) {
        return Err(Error::InvalidVAddr);
    }
    let mut fname = memory::read_utf8(&v_space, fname_ptr).await?;

    if let Ok(dir) = get_root_dir(&v_space, process, *obj_attr_ptr, profile).await {
        fname = format!("{}\\{}", dir, fname);
    }

    Ok(fname)
}

async fn get_root_dir(
    v_space: &IA32eVirtual,
    process: IA32eAddrT,
    obj_attr_ptr: PhysicalAddrT,
    profile: &RekallProfile,
) -> Result<String, Error> {
    let root_dir_ptr_rva =
        profile.get_struct_field_offset("_OBJECT_ATTRIBUTES", "RootDirectory")?;
    let root_dir_handle = v_space
        .read(obj_attr_ptr + root_dir_ptr_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let root_dir_handle = u64::from_ne_bytes(root_dir_handle[..].try_into().unwrap());
    if root_dir_handle == 0 {
        return Err(Error::InvalidVAddr);
    }

    let root_dir_ptr = handle_table::get_obj_by(v_space, root_dir_handle, process, profile).await?;
    let body_rva = profile.get_struct_field_offset("_OBJECT_HEADER", "Body")?;
    let name_rva = profile.get_struct_field_offset("_FILE_OBJECT", "FileName")?;
    let dir_name = memory::read_utf8(&v_space, root_dir_ptr + body_rva + name_rva).await?;
    Ok(dir_name)
}