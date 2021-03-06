use std::env;
use std::env::Args;
use std::error;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::fs::Permissions;
use std::io;
use std::mem;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::process;

use async_std::prelude::*;
use async_std::task;

use smol::Async;

use kvmi::message::*;
use kvmi::net::Stream;
use kvmi::{
    Action, Domain, DomainBuilder, Event, EventExtra, EventKind, HSToWire, PageAccessEntryBuilder,
};

use ArgsErrorKind::*;
use ErrorKind::*;

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    env_logger::init();

    let args = env::args();
    let result = parse_args(args);
    let path = match result {
        Err(e) => {
            eprintln!("{}", e);
            return exitcode::USAGE;
        }
        Ok(path) => path,
    };

    match task::block_on(listen(&path)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{}", e);
            e.as_exit_code()
        }
    }
}

async fn listen(path: &str) -> Result<i32, ListenError> {
    let listener = Async::<UnixListener>::bind(path).map_err(|e| ListenError::new(Bind, e))?;
    println!("Listening for connections");

    fs::set_permissions(path, Permissions::from_mode(0o666))
        .map_err(|e| ListenError::new(Bind, e))?;

    if let Some(stream) = listener.incoming().next().await {
        println!("Accepted a new connection");
        let stream = stream.map_err(|e| ListenError::new(Accept, e))?;

        let dom = DomainBuilder::new(Stream::from(stream));
        let (mut dom, mut event_rx, deserializer) = dom
            .handshake(|_name, _uuid, _start_t| {
                println!("performing handshake");
                Some(HSToWire::new())
            })
            .await
            .map_err(|e| ListenError::new(Handshake, e))?;
        println!("handshake done");

        let ver = dom
            .send(GetVersion)
            .await
            .map_err(|e| ListenError::new(GetInfo, e))?;
        println!("KVMI version: {}", ver);

        pause_vm(&mut dom).await?;

        let max = dom
            .send(GetMaxGfn)
            .await
            .map_err(|e| ListenError::new(GetInfo, e))?;
        println!("max gfn: 0x{:x?}", max);

        let mut pf_test_enabled = false;
        while let Some(event) = event_rx.next().await {
            handle_event(&mut dom, event, &mut pf_test_enabled)
                .await
                .map_err(|e| ListenError::new(HandleEvent, e))?;
        }

        mem::drop(dom);
        deserializer.await;
        return Err(ListenError::new(WaitEvent, "event stream broken"));
    }

    Ok(exitcode::OK)
}

async fn handle_event<T: AsRawFd>(
    dom: &mut Domain<T>,
    event: Event,
    pf_test_enabled: &mut bool,
) -> Result<(), kvmi::Error> {
    use Action::*;
    use EventExtra::*;

    let extra = event.get_extra();
    match extra {
        PauseVCPU => {
            println!("PauseVCPU event, continuing");
            enable_events(dom, event.get_vcpu()).await?;
            if !*pf_test_enabled {
                *pf_test_enabled = start_pf_test(dom, &event).await?;
            }
            dom.send(CommonEventReply::new(&event, Continue).unwrap())
                .await
                .map(|_| ())
        }
        PF(pf) => {
            let pf_ref = pf.as_raw_ref();
            println!(
                "PF event:\ngva 0x{:x?}\ngpa 0x{:x?}\naccess 0x{:x?}\nvcpu {}",
                pf_ref.gva,
                pf_ref.gpa,
                pf_ref.access,
                event.get_vcpu()
            );
            dom.send(PFEventReply::new(&event, Retry).unwrap())
                .await
                .map(|_| ())
        }
        CR(cr) => {
            if !*pf_test_enabled {
                let started = start_pf_test(dom, &event).await?;
                if started {
                    *pf_test_enabled = true;
                    // disable CR events when the test is started
                    dom.send(VcpuControlEvent::new(
                        event.get_vcpu(),
                        EventKind::CR,
                        false,
                    ))
                    .await?;
                }
            } else {
                dom.send(VcpuControlEvent::new(
                    event.get_vcpu(),
                    EventKind::CR,
                    false,
                ))
                .await?;
            }

            println!(
                "CR{} event, old: 0x{:x?}, new: 0x{:x?}, continuing",
                cr.get_cr_num(),
                cr.get_old_val(),
                cr.get_new_val()
            );
            dom.send(CREventReply::new(&event, Continue, cr.get_new_val()).unwrap())
                .await
                .map(|_| ())
        }
        _ => Err(io::Error::new(io::ErrorKind::Other, "unexpected event").into()),
    }
}

const PAGE_SIZE: u64 = 4096;
const TEST_PAGE_NUM: u64 = 40;
async fn start_pf_test<T: AsRawFd>(
    dom: &mut Domain<T>,
    event: &Event,
) -> Result<bool, kvmi::Error> {
    let cr3 = event.get_arch().sregs.cr3;
    let pt_addr = cr3 & !0xfff;
    if pt_addr == 0 {
        return Ok(false);
    }

    let mut msg = SetPageAccess::new();
    let mut builder = PageAccessEntryBuilder::new(0);
    builder.set_read().set_execute();
    for i in 0..TEST_PAGE_NUM {
        let entry = builder.gpa(pt_addr + i * PAGE_SIZE).build();
        msg.push(entry);
    }
    dom.send(msg).await?;

    Ok(true)
}

async fn pause_vm<T: AsRawFd>(dom: &mut Domain<T>) -> Result<(), ListenError> {
    let num = dom
        .send(GetVCPUNum)
        .await
        .map_err(|e| ListenError::new(GetInfo, e))?;
    println!("vcpu number: {}", num);
    dom.send(PauseVCPUs::new(num).unwrap())
        .await
        .map_err(|e| ListenError::new(PauseVM, e))?;
    Ok(())
}

async fn enable_events<T: AsRawFd>(dom: &mut Domain<T>, vcpu: u16) -> Result<(), kvmi::Error> {
    use EventKind::*;

    println!("enabling page fault and CR events");
    dom.send(VcpuControlEvent::new(vcpu, PF, true)).await?;
    dom.send(VcpuControlEvent::new(vcpu, CR, true)).await?;
    if vcpu == 0 {
        dom.send(ControlCR::new(vcpu, 3, true)).await?;
    }
    dom.send(ControlCR::new(vcpu, 4, true)).await?;
    Ok(())
}

#[derive(Debug)]
struct ListenError {
    kind: ErrorKind,
    error: Box<dyn error::Error + Send + Sync>,
    errno: i32,
}

impl ListenError {
    fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        let errno = match kind {
            Bind => exitcode::UNAVAILABLE,
            Accept | Handshake | GetInfo | WaitEvent | PauseVM | HandleEvent => exitcode::IOERR,
        };
        Self {
            kind,
            error: error.into(),
            errno,
        }
    }

    fn as_exit_code(&self) -> i32 {
        self.errno
    }
}

impl Display for ListenError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.kind {
            Bind => write!(f, "failed to bind to path: {}", self.error),
            Accept => write!(f, "failed to accept stream: {}", self.error),
            Handshake => write!(f, "failed to do handshake: {}", self.error),
            GetInfo => write!(f, "failed to get the info from KVMI: {}", self.error),
            WaitEvent => write!(f, "error while waiting for events: {}", self.error),
            HandleEvent => write!(f, "error handling events: {}", self.error),
            PauseVM => write!(f, "error while pausing all the vcpus: {}", self.error),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Bind,
    Accept,
    Handshake,
    GetInfo,
    WaitEvent,
    HandleEvent,
    PauseVM,
}

#[derive(Debug)]
enum ArgsErrorKind {
    WrongNumber,
}

#[derive(Debug)]
struct ArgsError {
    kind: ArgsErrorKind,
}

impl Error for ArgsError {}

impl ArgsError {
    fn new(kind: ArgsErrorKind) -> Self {
        ArgsError { kind }
    }
}

impl Display for ArgsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.kind {
            WrongNumber => write!(f, "wrong number of arguments"),
        }
    }
}

fn parse_args(mut args: Args) -> Result<String, ArgsError> {
    let path = args.nth(1);
    if let Some(path) = path {
        if args.next().is_none() {
            return Ok(path);
        }
    }
    Err(ArgsError::new(WrongNumber))
}
