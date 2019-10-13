use std::env;
use std::env::Args;
use std::error;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::process;

use async_std::os::unix::net::UnixListener;
use async_std::prelude::*;
use async_std::task;

use kvmi::Message::*;
use kvmi::{Action, Domain, DomainBuilder, Event, EventExtra, EventReplyReqExtra, HSToWire, Reply};

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
    let listener = UnixListener::bind(path)
        .await
        .map_err(|e| ListenError::new(Bind, e))?;
    println!("Listening for connections");

    fs::set_permissions(path, Permissions::from_mode(0o666))
        .map_err(|e| ListenError::new(Bind, e))?;

    while let Some(stream) = listener.incoming().next().await {
        println!("Accepted a new connection");
        let stream = stream.map_err(|e| ListenError::new(Accept, e))?;

        let dom = DomainBuilder::new(stream);
        let (mut dom, mut event_rx) = dom
            .handshake(|_name, _uuid, _start_t| {
                println!("performing handshake");
                Some(HSToWire::new())
            })
            .await
            .map_err(|e| ListenError::new(Handshake, e))?;
        println!("handshake done");

        let reply = dom
            .send(GetVersion)
            .await
            .map_err(|e| ListenError::new(GetInfo, e))?;
        if let Some(Reply::Version(ver)) = reply {
            println!("KVMI version: {}", ver);
        }

        pause_vm(&mut dom).await?;

        let reply = dom
            .send(GetMaxGfn)
            .await
            .map_err(|e| ListenError::new(GetInfo, e))?;
        if let Some(Reply::MaxGfn(max)) = reply {
            println!("max gfn: 0x{:x?}", max);
        }

        while let Some(event) = event_rx.next().await {
            handle_event(&mut dom, event)
                .await
                .map_err(|e| ListenError::new(HandleEvent, e))?;
        }

        return Err(ListenError::new(WaitEvent, "event stream broken"));
    }

    Ok(exitcode::OK)
}

async fn handle_event(dom: &mut Domain, event: Event) -> Result<Option<Reply>, kvmi::Error> {
    use Action::*;
    use EventExtra::*;

    println!("event: {:?}", event);

    let extra = event.get_extra();
    let reply = match extra {
        PauseVCPU => {
            println!("PauseVCPU event, continuing");
            event.new_reply(Continue, None)
        }
        PF(pf) => {
            println!("PF event, retrying");
            println!("PF event: {:?}", pf);
            event.new_reply(Retry, Some(EventReplyReqExtra::new_pf_extra()))
        }
        _ => event.new_reply(Continue, None),
    }?;

    dom.send(EventReply(reply)).await
}

async fn pause_vm(dom: &mut Domain) -> Result<(), ListenError> {
    let reply = dom
        .send(GetVCPUNum)
        .await
        .map_err(|e| ListenError::new(GetInfo, e))?;
    if let Some(Reply::VCPUNum(num)) = reply {
        println!("vcpu number: {}", num);
    }
    dom.send(PauseAllVCPU)
        .await
        .map_err(|e| ListenError::new(PauseVM, e))?;
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
            Ok(path)
        } else {
            Err(ArgsError::new(WrongNumber))
        }
    } else {
        Err(ArgsError::new(WrongNumber))
    }
}
