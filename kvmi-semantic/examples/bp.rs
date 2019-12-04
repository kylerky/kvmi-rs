use async_std::os::unix::net::UnixListener;
use async_std::prelude::*;
use async_std::task;

use std::fs;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use kvmi_semantic::address_space::*;
use kvmi_semantic::event::*;
use kvmi_semantic::{Action, Domain, Error, HSToWire, RekallProfile};

use structopt::StructOpt;

use log::debug;

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
            "ImageFileName": [1104, ["Array", {
             "count": 15,
             "target": "unsigned char"
            }]]
        }],
        "_KPROCESS": [736, {
            "DirectoryTableBase": [40, ["unsigned long long", {}]]
        }],
        "_LIST_ENTRY": [16, {
            "Blink": [8, ["Pointer", {
                "target": "_LIST_ENTRY"
            }]],
            "Flink": [0, ["Pointer", {
                "target": "_LIST_ENTRY"
            }]]
        }],
        "_KUSER_SHARED_DATA": [1808, {
            "NtMajorVersion": [620, ["unsigned long", {}]],
            "NtMinorVersion": [624, ["unsigned long", {}]]
        }]
    }
}"#;

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
        let dom = Domain::new(
            stream,
            |_, _, _| Some(HSToWire::new()),
            rekall_profile,
            opt.ptb.take(),
        )
        .await?;

        let v_addr = dom.get_kernel_base_va() + dom.get_kfunc_offset("ZwOpenFile")?;
        let v_space = dom.get_vspace();
        let p_space = v_space.get_base();
        let gpa = v_space
            .translate_v2p(v_addr)
            .await?
            .expect("Cannot translate address of ZwOpenFile");

        dom.pause_vm().await?;

        let orig = p_space.read(gpa, 1).await?[0];

        let event_rx = dom.get_event_stream();
        let mut bp_set = false;
        while let Some(event) = event_rx.recv().await {
            handle_event(&dom, orig, event, gpa, &mut bp_set).await?;
        }
    }

    Ok(())
}

async fn handle_event(
    dom: &Domain,
    orig: u8,
    event: Event,
    gpa: u64,
    bp_set: &mut bool,
) -> Result<(), Error> {
    use EventExtra::*;

    let extra = event.get_extra();
    match extra {
        PauseVCPU => handle_pause(dom, &event, gpa, bp_set).await?,
        Breakpoint(bp) => handle_bp(dom, orig, &event, bp, gpa).await?,
        SingleStep(ss) => handle_ss(dom, gpa, &event, ss).await?,
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
    debug!("VCPU {} paused, enabling BP and single step event", vcpu);
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
    dom: &Domain,
    orig: u8,
    event: &Event,
    extra: &KvmiEventBreakpoint,
    gpa: u64,
) -> Result<(), Error> {
    debug!(
        "BP event: 0x{:x?}, insn_len: {}",
        extra.get_gpa(),
        extra.get_insn_len()
    );
    if extra.get_gpa() == gpa {
        dom.resume_from_bp(orig, event, extra, true).await?;
    } else {
        dom.reply(event, Action::Continue).await?;
    }
    Ok(())
}

async fn handle_ss(
    dom: &Domain,
    gpa: PhysicalAddrT,
    event: &Event,
    _ss: &KvmiEventSingleStep,
) -> Result<(), Error> {
    use Action::*;

    debug!("Single step event, vcpu: {}", event.get_vcpu());

    // reset the breakpoint
    debug!("Restoring breakpoint at 0x{:x?}", gpa);
    dom.set_bp_by_physical(gpa).await?;
    // quit single step mode
    dom.toggle_single_step(event.get_vcpu(), false).await?;
    dom.reply(event, Continue).await?;
    Ok(())
}
