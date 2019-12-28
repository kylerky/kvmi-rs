use async_std::os::unix::net::UnixListener;
use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::task;

use std::convert::TryInto;
use std::fs;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::memory;
use kvmi_semantic::tracing::functions::MSx64;
use kvmi_semantic::{Action, Domain, Error, HSToWire, RekallProfile};

use structopt::StructOpt;

use log::{debug, error, info};

use signal_hook::flag;

const REKALL_PROFILE: &str = r#"
{
    "$CONSTANTS": {
       "PsActiveProcessHead": 4405536,
       "PsInitialSystemProcess": 5698464
    },
    "$FUNCTIONS": {
        "KiSystemCall32Shadow": 3468800,
        "KiSystemCall64Shadow": 3469632,
        "NtOpenFile": 6497456,
        "ZwOpenFile": 1807424
    },
    "$STRUCTS": {
        "_EPROCESS": [2176, {
            "ActiveProcessLinks": [752, ["_LIST_ENTRY", {}]],
            "UniqueProcessId": [744, ["Pointer", {
                "target": "Void"
            }]],
            "ObjectTable": [1048, ["Pointer", {
                "target": "_HANDLE_TABLE"
            }]],
            "ImageFileName": [1104, ["Array", {
                "count": 15,
                "target": "unsigned char"
            }]]
        }],
        "_KPROCESS": [736, {
            "DirectoryTableBase": [40, ["unsigned long long", {}]]
        }],
        "_KTHREAD": [1536, {
            "Process": [544, ["Pointer", {
                "target": "_KPROCESS"
            }]]
        }],
        "_LIST_ENTRY": [16, {
            "Blink": [8, ["Pointer", {
                "target": "_LIST_ENTRY"
            }]],
            "Flink": [0, ["Pointer", {
                "target": "_LIST_ENTRY"
            }]]
        }],
        "_KPCR": [36992, {
            "Prcb": [384, ["_KPRCB", {}]]
        }],
        "_KPRCB": [36608, {
            "CurrentThread": [8, ["Pointer", {
                "target": "_KTHREAD"
            }]]
        }],
        "_HANDLE_TABLE_ENTRY": [16, {
        }],
        "_HANDLE_TABLE": [128, {
            "TableCode": [8, ["unsigned long long", {}]]
        }],
        "_OBJECT_HEADER": [56, {
            "Body": [48, ["_QUAD", {}]]
        }],
        "_OBJECT_ATTRIBUTES": [48, {
            "ObjectName": [16, ["Pointer", {
                "target": "_UNICODE_STRING"
            }]],
            "RootDirectory": [8, ["Pointer", {
                "target": "Void"
            }]]
        }],
        "_FILE_OBJECT": [216, {
            "FileName": [88, ["_UNICODE_STRING", {}]]
        }],
        "_KUSER_SHARED_DATA": [1808, {
            "NtMajorVersion": [620, ["unsigned long", {}]],
            "NtMinorVersion": [624, ["unsigned long", {}]]
        }]
    }
}"#;

const CPL_MASK: u16 = 3;

#[derive(StructOpt)]
#[structopt(name = "get_ptb")]
struct Opt {
    socket: PathBuf,

    #[structopt(short, long)]
    ptb: Option<u64>,
}

fn main() -> Result<(), io::Error> {
    let opt = Opt::from_args();

    env_logger::init();

    task::block_on(listen(opt))
}

async fn listen(mut opt: Opt) -> Result<(), io::Error> {
    let listener = UnixListener::bind(&opt.socket).await?;
    println!("Listening for connections");

    fs::set_permissions(&opt.socket, Permissions::from_mode(0o666))?;
    if let Some(stream) = listener.incoming().next().await {
        println!("Accepted a new connection");
        let stream = stream?;

        let rekall_profile: RekallProfile = serde_json::from_str(REKALL_PROFILE)?;
        let mut dom = Domain::new(
            stream,
            |_, _, _| Some(HSToWire::new()),
            rekall_profile,
            opt.ptb.take(),
        )
        .await?;

        let profile = dom.get_profile();
        let v_addr = dom.get_kernel_base_va() + profile.get_kfunc_offset("NtOpenFile")?;
        let v_space = dom.get_k_vspace();
        let p_space = v_space.get_base();
        let gpa = v_space
            .lookup(v_addr)
            .await?
            .expect("Cannot translate address of NtOpenFile");

        dom.pause_vm().await?;

        let orig = p_space.read(gpa, 1).await?[0];

        let exit = Arc::new(AtomicBool::new(false));
        flag::register(signal_hook::SIGINT, Arc::clone(&exit))?;

        let event_rx = dom.get_event_stream().clone();
        let mut bp_set = false;
        while let Some(event) = event_rx.recv().await {
            if let Err(e) = handle_event(&mut dom, orig, event, gpa, &mut bp_set).await {
                clear_bp(&dom, gpa, orig).await;
                return Err(e.into());
            }
            if exit.load(Ordering::Relaxed) {
                break;
            }
        }
        shutdown(dom, gpa, orig).await?;
    }

    Ok(())
}

async fn clear_bp(dom: &Domain, gpa: PhysicalAddrT, orig: u8) {
    debug!("Clearing bp");
    let res = dom.clear_bp_by_physical(gpa, orig).await;
    if let Err(err) = res {
        error!("Error clearing bp: {}", err);
    }
}

async fn handle_event(
    dom: &mut Domain,
    orig: u8,
    event: Event,
    gpa: u64,
    bp_set: &mut bool,
) -> Result<(), Error> {
    use EventExtra::*;

    let extra = event.get_extra();
    match extra {
        PauseVCPU => handle_pause(dom, &event, gpa, bp_set).await?,
        Breakpoint(bp) => handle_bp(dom, orig, &event, bp, gpa, true).await?,
        SingleStep(ss) => handle_ss(dom, gpa, &event, ss, true).await?,
        PF(pf) => handle_pf(dom, &event, pf).await?,
        _ => debug!("Received event: {:?}", event),
    }
    Ok(())
}

async fn handle_pause(
    dom: &Domain,
    event: &Event,
    gpa: u64,
    bp_set: &mut bool,
) -> Result<(), Error> {
    use Action::*;
    use EventKind::*;

    let vcpu = event.get_vcpu();
    dom.toggle_event(vcpu, PF, true).await?;
    dom.toggle_event(vcpu, Breakpoint, true).await?;
    dom.toggle_event(vcpu, SingleStep, true).await?;

    if !*bp_set {
        debug!("bp address: {:x?}", gpa);
        dom.set_bp_by_physical(gpa).await?;
        *bp_set = true;
    }

    dom.reply(event, Continue).await?;
    Ok(())
}

async fn handle_bp(
    dom: &mut Domain,
    orig: u8,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    gpa: u64,
    enable_ss: bool,
) -> Result<(), Error> {
    if extra.get_gpa() != gpa {
        dom.reply(event, Action::Continue).await?;
        return Ok(());
    }

    let sregs = &event.get_arch().sregs;
    let cs_sel = sregs.cs.selector;
    // current privilege level
    let cpl = cs_sel & CPL_MASK;

    if cpl != 0 {
        dom.resume_from_bp(orig, event, extra, enable_ss).await?;
        return Err(Error::Unsupported(String::from(
            "Reading process info not in ring 0 is not supported",
        )));
    }

    let pid = get_pid(dom, event, sregs).await?;
    println!("pid: {}", pid);

    match get_file_info(dom, event, sregs).await {
        Ok(_) => {
            dom.resume_from_bp(orig, event, extra, enable_ss).await?;
            Ok(())
        }
        Err(e) => {
            if let Err(err) = dom.resume_from_bp(orig, event, extra, false).await {
                error!("Error resuming from bp: {}", err);
            }
            Err(e)
        }
    }
}

async fn handle_pf(dom: &mut Domain, event: &Event, extra: &KvmiEventPF) -> Result<(), Error> {
    dom.handle_pf(event, extra).await
}

async fn get_pid(dom: &mut Domain, event: &Event, sregs: &kvm_sregs) -> Result<u64, Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let uid_rva = profile.get_struct_field_offset("_EPROCESS", "UniqueProcessId")?;
    let arch = event.get_arch();
    let process = dom.get_current_process(&arch.sregs).await?;
    let pid = v_space
        .read(process + uid_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
    Ok(pid)
}

async fn get_file_info(dom: &mut Domain, event: &Event, sregs: &kvm_sregs) -> Result<(), Error> {
    let v_space = dom.get_vspace(kvmi_semantic::get_ptb_from(sregs)).clone();
    let profile = dom.get_profile();

    let regs = &event.get_arch().regs;
    let args = MSx64::new(&v_space, regs, 3).await?;
    let obj_attr_ptr = args.get(2).unwrap();
    if *obj_attr_ptr == 0 {
        return Ok(());
    }

    let fname_rva = profile.get_struct_field_offset("_OBJECT_ATTRIBUTES", "ObjectName")?;
    let fname_ptr = v_space
        .read(obj_attr_ptr + fname_rva, 8)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let fname_ptr = u64::from_ne_bytes(fname_ptr[..].try_into().unwrap());
    if fname_ptr == 0 || !IA32eVirtual::is_canonical(fname_ptr) {
        return Ok(());
    }
    let fname = memory::read_utf16(&v_space, fname_ptr).await?;
    println!("fname: {}", fname);

    Ok(())
}

async fn handle_ss(
    dom: &Domain,
    gpa: PhysicalAddrT,
    event: &Event,
    _ss: &KvmiEventSingleStep,
    restore: bool,
) -> Result<(), Error> {
    use Action::*;

    // reset the breakpoint
    if restore {
        dom.set_bp_by_physical(gpa).await?;
    }
    // quit single step mode
    dom.toggle_single_step(event.get_vcpu(), false).await?;
    dom.reply(event, Continue).await?;
    Ok(())
}

async fn shutdown(mut dom: Domain, gpa: PhysicalAddrT, orig: u8) -> Result<(), Error> {
    use EventExtra::*;

    info!("cleaning up");
    dom.pause_vm().await?;
    let event_rx = dom.get_event_stream().clone();

    let vcpu_num = dom.get_vcpu_num().await? as usize;
    debug!("{} vcpus to pause", vcpu_num);
    let mut cnt = 0;
    while let Some(event) = event_rx.recv().await {
        let extra = event.get_extra();
        match extra {
            PauseVCPU => {
                use EventKind::*;
                let vcpu = event.get_vcpu();
                info!("vcpu {} paused", vcpu);
                dom.toggle_event(vcpu, Breakpoint, false).await?;
                dom.toggle_event(vcpu, SingleStep, false).await?;

                cnt += 1;
                if cnt == vcpu_num {
                    clear_bp(&dom, gpa, orig).await;
                    dom.reply(&event, Action::Continue).await?;
                    break;
                }
                dom.reply(&event, Action::Continue).await?;
            }
            Breakpoint(bp) => handle_bp(&mut dom, orig, &event, bp, gpa, false).await?,
            SingleStep(ss) => handle_ss(&dom, gpa, &event, ss, false).await?,
            _ => debug!("Received event: {:?}", event),
        }
    }
    while !event_rx.is_empty() {
        if let Some(event) = event_rx.recv().await {
            let extra = event.get_extra();
            match extra {
                Breakpoint(bp) => handle_bp(&mut dom, orig, &event, bp, gpa, false).await?,
                SingleStep(ss) => handle_ss(&dom, gpa, &event, ss, false).await?,
                _ => debug!("Received event: {:?}", event),
            }
        }
    }
    Ok(())
}
