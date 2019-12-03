use std::cmp;
use std::collections::HashMap;
use std::convert::TryInto;
use std::error;
use std::ffi::{CStr, FromBytesWithNulError};
use std::fmt::{self, Display, Formatter};
use std::io;
use std::marker::Unpin;
use std::mem::{self, size_of, transmute};
use std::str::Utf8Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_std::io::prelude::*;
use async_std::io::BufReader;
use async_std::os::unix::io::{AsRawFd, RawFd};
use async_std::sync::{self, Mutex, Receiver, Sender};
use async_std::task::{self, JoinHandle};

use log::{debug, error};

use nix::errno::Errno;
use nix::sys::socket::{self, MsgFlags};
use nix::sys::uio::IoVec;

use mio::unix::{EventedFd, UnixReady};
use mio::{Events, Poll, PollOpt, Ready, Token};

use futures::future::FutureExt;
use futures::select;
use futures::stream::StreamExt;

#[macro_use]
extern crate lazy_static;

mod c_ffi;
use c_ffi::*;
pub use c_ffi::{
    kvm_msr_entry, kvmi_event_arch, kvmi_event_pf, kvmi_get_registers_reply, HSToWire,
    KvmiEventBreakpoint, KvmiEventCR, KvmiEventPF, KvmiEventSingleStep, PageAccessEntry,
};

mod utils;
use utils::*;

pub mod message;
use message::*;

type MsgHeader = kvmi_msg_hdr;
type ErrorCode = kvmi_error_code;

pub type Result<T> = std::result::Result<T, Error>;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Action {
    Continue = KVMI_EVENT_ACTION_CONTINUE as u8,
    Retry = KVMI_EVENT_ACTION_RETRY as u8,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum EventKind {
    PF = KVMI_EVENT_PF as u16,
    CR = KVMI_EVENT_CR as u16,
    Breakpoint = KVMI_EVENT_BREAKPOINT as u16,
    SingleStep = KVMI_EVENT_SINGLESTEP as u16,
}

pub struct DomainBuilder<T> {
    reader: BufReader<T>,
    fd: RawFd,
}

impl<T> DomainBuilder<T>
where
    T: Write + Read + Send + AsRawFd + Unpin + 'static,
{
    pub fn new(stream: T) -> Self {
        let fd = stream.as_raw_fd();
        Self {
            reader: BufReader::new(stream),
            fd,
        }
    }

    const MIN_HS_DATA: u32 = (size_of::<HSFromWire>() - size_of::<[u8; 64]>()) as u32;
    const MAX_HS_DATA: u32 = 64 * 1024;
    pub async fn handshake<F>(self, validate: F) -> Result<(Domain, Receiver<Event>)>
    where
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let mut reader = self.reader;
        let (name, uuid, start_time) = Self::read_handshake_data(&mut reader).await?;

        let fd = self.fd;

        let (event_tx, event_rx) = sync::channel(10);
        let (req_tx, req_rx) = sync::channel(1);
        let (err_tx, err_rx) = sync::channel(1);
        let (shutdown, sd_rx) = sync::channel(1);
        let deserializer = task::spawn(Self::deserializer(reader, event_tx, req_rx, err_tx, sd_rx));

        let to_wire = match validate(&name, &uuid[..], start_time) {
            None => return Err(Error::from(ErrorKind::Handshake)),
            Some(i) => i,
        };
        let to_wire_slice = unsafe { any_as_u8_slice(&to_wire) };
        let io_vec = vec![to_wire_slice.to_vec()];
        Domain::request(fd, io_vec).await?;

        Ok((
            Domain {
                name,
                uuid,
                start_time,
                req_handle: Mutex::new(ReqHandle { fd, req_tx }),
                err_rx,
                shutdown: Some(shutdown),
                deserializer: Some(deserializer),
            },
            event_rx,
        ))
    }
    async fn read_handshake_data(reader: &mut BufReader<T>) -> Result<(String, [u8; 16], i64)> {
        let mut buffer = [0u8; size_of::<HSFromWire>()];
        const SIZE_SZ: usize = size_of::<u32>();

        // get the size of the wire data
        reader.read_exact(&mut buffer[0..SIZE_SZ]).await?;
        let slice = &buffer[0..SIZE_SZ];
        let incoming = u32::from_ne_bytes(slice.try_into().unwrap());
        let mut size = incoming;

        // checking constraints of wire data size
        if size < Self::MIN_HS_DATA {
            return Err(Error::from(ErrorKind::HandshakeNoData));
        }
        if size > Self::MAX_HS_DATA {
            return Err(Error::from(ErrorKind::Handshake2Big));
        }

        // get the rest of the data
        size = cmp::min(size, size_of::<HSFromWire>() as u32);
        reader
            .read_exact(&mut buffer[SIZE_SZ..(size as usize)])
            .await?;

        let from_wire = {
            let mut from_wire: HSFromWire = unsafe { transmute(buffer) };
            from_wire.size = size;
            from_wire
        };
        debug!(
            "Wire data:\n\
             size: {}\n\
             uuid: {:?}\n\
             padding: {}",
            from_wire.size, from_wire.uuid, from_wire.padding
        );

        let rest = (incoming - size) as usize;
        if rest > 0 {
            Self::consume_bytes(reader, rest).await?;
        }

        let name_len = size - Self::MIN_HS_DATA;
        let name = if name_len > 0 {
            let name_slice = &from_wire.name[..(name_len as usize)];
            let c_str = CStr::from_bytes_with_nul(name_slice);
            match c_str {
                Ok(c_str) => String::from(c_str.to_str()?),
                Err(_) => String::new(),
            }
        } else {
            String::new()
        };

        Ok((name, from_wire.uuid, from_wire.start_time))
    }

    async fn deserializer(
        reader: BufReader<T>,
        event_tx: Sender<Event>,
        req_rx: Receiver<Request>,
        err_tx: Sender<Error>,
        sd_rx: Receiver<()>,
    ) {
        let mut sd_rx = sd_rx.fuse();
        select! {
            x = Self::deserializer_inner(reader, event_tx, req_rx).fuse() =>
                if let Err(e) = x {
                    err_tx.send(e).await;
                },

            _ = sd_rx.next() => (),
        };
    }

    async fn deserializer_inner(
        mut reader: BufReader<T>,
        event_tx: Sender<Event>,
        req_rx: Receiver<Request>,
    ) -> Result<()> {
        loop {
            let header = Self::recv_header(&mut reader).await?;
            match header.id as u32 {
                KVMI_EVENT => Self::recv_event(&mut reader, &event_tx, header).await?,
                _ => Self::recv_reply(&mut reader, &req_rx, header).await?,
            }
        }
    }

    async fn recv_reply(
        mut reader: &mut BufReader<T>,
        req_rx: &Receiver<Request>,
        header: MsgHeader,
    ) -> Result<()> {
        let req = match req_rx.recv().await {
            None => {
                error!("Unexpected closure of the request channel");
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "cannot get requests").into(),
                );
            }
            Some(req) => req,
        };

        if req.kind != header.id || req.seq != header.seq {
            error!(
                "Wrong message header\nReceived: {:?}\nrequest {:?}",
                header, req
            );
            return Err(io::Error::from_raw_os_error(libc::ENOMSG).into());
        }

        let size = Self::recv_error_code(&mut reader, header.size).await?;
        let (buffer, actual_sz) = Self::recv_reply_data(&mut reader, size, req.size).await?;

        let rest = (size as usize) - actual_sz;
        if rest > 0 {
            Self::consume_bytes(reader, (size as usize) - actual_sz).await?;
        }

        req.result.send(buffer).await;
        Ok(())
    }

    const KVMI_MSG_SZ: usize = 4096 - 8;
    async fn recv_event(
        reader: &mut BufReader<T>,
        event_tx: &Sender<Event>,
        header: MsgHeader,
    ) -> Result<()> {
        if header.size as usize > Self::KVMI_MSG_SZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The KVMI message to receive is too big",
            )
            .into());
        }

        let mut buffer = vec![0; header.size as usize];
        reader.read_exact(&mut buffer[..]).await?;

        let event = Self::construct_event(buffer, header.seq)?;
        event_tx.send(event).await;

        Ok(())
    }

    const EVENT_MIN_SZ: u16 = 6;
    fn construct_event(buffer: Vec<u8>, seq: u32) -> Result<Event> {
        let mut sz = [0u8; size_of::<u16>()];
        sz.clone_from_slice(&buffer[..size_of::<u16>()]);
        let sz: u16 = unsafe { transmute(sz) };

        if sz < Self::EVENT_MIN_SZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Incoming message is too short",
            )
            .into());
        }
        if sz as usize > buffer.len() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "Not enough data from KVM").into(),
            );
        }

        let (common, rest) = buffer.split_at(sz as usize);

        // construct the common part of the event
        let useful = cmp::min(sz as usize, size_of::<KvmiEvent>());
        let common: KvmiEvent = unsafe {
            let mut buf = [0u8; size_of::<KvmiEvent>()];
            buf[..useful].clone_from_slice(&common[..useful]);
            transmute(buf)
        };

        let sz = match EVENT_SZ_MAP.get(&(common.0.event as u32)) {
            None => {
                error!("unkown event: {}", common.0.event);
                return Err(Error::from(ErrorKind::UnknownKVMIEvent));
            }
            Some(s) => s,
        };

        let useful = cmp::min(*sz, rest.len());
        let extra = Self::get_extra(useful, *sz as usize, rest, &common)?;
        Ok(Event { common, extra, seq })
    }

    fn get_extra(useful: usize, sz: usize, rest: &[u8], common: &KvmiEvent) -> Result<EventExtra> {
        let details = {
            let buf = vec![0; sz];
            let mut buf = buf.into_boxed_slice();
            buf[..useful].clone_from_slice(&rest[..useful]);
            buf
        };

        let extra = unsafe {
            match common.0.event as u32 {
                KVMI_EVENT_CR => EventExtra::CR(boxed_slice_to_type(details)),
                KVMI_EVENT_MSR => EventExtra::MSR(boxed_slice_to_type(details)),
                KVMI_EVENT_BREAKPOINT => EventExtra::Breakpoint(boxed_slice_to_type(details)),
                KVMI_EVENT_PF => EventExtra::PF(boxed_slice_to_type(details)),
                KVMI_EVENT_TRAP => EventExtra::Trap(boxed_slice_to_type(details)),
                KVMI_EVENT_DESCRIPTOR => EventExtra::Descriptor(boxed_slice_to_type(details)),
                KVMI_EVENT_SINGLESTEP => EventExtra::SingleStep(boxed_slice_to_type(details)),
                KVMI_EVENT_CREATE_VCPU => EventExtra::CreateVCPU,
                KVMI_EVENT_HYPERCALL => EventExtra::HyperCall,
                KVMI_EVENT_PAUSE_VCPU => EventExtra::PauseVCPU,
                KVMI_EVENT_UNHOOK => EventExtra::Unhook,
                KVMI_EVENT_XSETBV => EventExtra::XSetBV,
                _ => {
                    error!(
                        "unkown event: {} (really should not be here)",
                        common.0.event
                    );
                    return Err(Error::from(ErrorKind::UnknownKVMIEvent));
                }
            }
        };
        Ok(extra)
    }

    async fn recv_header(reader: &mut BufReader<T>) -> Result<MsgHeader> {
        let header: MsgHeader = {
            let mut buffer = [0u8; size_of::<MsgHeader>()];
            reader.read_exact(&mut buffer[..]).await?;

            unsafe { transmute(buffer) }
        };

        Ok(header)
    }

    async fn recv_error_code(reader: &mut BufReader<T>, size: u16) -> Result<u16> {
        if size < (size_of::<ErrorCode>() as u16) {
            return Err(io::Error::from_raw_os_error(libc::ENODATA).into());
        }

        let mut buffer = [0u8; size_of::<ErrorCode>()];
        reader.read_exact(&mut buffer[..]).await?;
        let err: ErrorCode = unsafe { transmute(buffer) };
        if err.err != 0 {
            error!("non zero error code from KVM: {}", err.err);
            return Err(io::Error::from_raw_os_error(err.as_os_error()).into());
        }
        Ok(size - (size_of::<ErrorCode>() as u16))
    }

    async fn recv_reply_data(
        reader: &mut BufReader<T>,
        size: u16,
        type_size: usize,
    ) -> Result<(Vec<u8>, usize)> {
        let mut buffer = vec![0; type_size];

        let actual_sz = cmp::min(size as usize, type_size);
        reader.read_exact(&mut buffer[..actual_sz]).await?;

        Ok((buffer, actual_sz))
    }

    async fn consume_bytes(reader: &mut BufReader<T>, nbytes: usize) -> Result<()> {
        let mut redundant = vec![];
        redundant.resize(nbytes as usize, 0u8);
        reader.read_exact(&mut redundant).await?;
        Ok(())
    }
}

pub struct Domain {
    uuid: [u8; 16],
    start_time: i64,
    name: String,
    req_handle: Mutex<ReqHandle>,
    err_rx: Receiver<Error>,
    shutdown: Option<Sender<()>>,
    deserializer: Option<JoinHandle<()>>,
}

struct ReqHandle {
    fd: RawFd,
    req_tx: Sender<Request>,
}

impl Drop for Domain {
    fn drop(&mut self) {
        // this is the only Sender for this Domain
        // dropping it will make deserializer return
        mem::drop(self.shutdown.take());
        task::block_on(self.deserializer.take().unwrap());
    }
}

impl Domain {
    const KVMI_TIMEOUT: Duration = Duration::from_millis(15_000);
    async fn request(fd: RawFd, vec: Vec<Vec<u8>>) -> Result<()> {
        let io_vec: Vec<IoVec<&[u8]>> = vec.iter().map(|i| IoVec::from_slice(&i[..])).collect();
        Self::send_msg(fd, &io_vec[..], Some(Self::KVMI_TIMEOUT))
    }
    fn send_msg(fd: RawFd, io_vec: &[IoVec<&[u8]>], timeout: Option<Duration>) -> Result<()> {
        // let flags = match MsgFlags::from_bits(libc::MSG_NOSIGNAL) {
        //     Some(f) => f,
        //     None => return Err(Error::from(ErrorKind::FlagNSig)),
        // };
        let flags = MsgFlags::empty();

        loop {
            match socket::sendmsg(fd, io_vec, &[], flags, None) {
                Ok(_) => return Ok(()),
                // wait and try again
                Err(nix::Error::Sys(Errno::EAGAIN)) => (),
                Err(e) => {
                    error!("error sending message through the socket: {:?}", e);
                    return Err(e.into());
                }
            }

            Self::io_ready_await(fd, Ready::writable(), timeout)?;
        }
    }

    fn io_ready_await(fd: RawFd, interest: Ready, timeout: Option<Duration>) -> Result<()> {
        debug!("waiting for socket to be writable");
        let poll = Poll::new()?;
        poll.register(
            &EventedFd(&fd),
            Token(0),
            interest | UnixReady::hup(),
            PollOpt::empty(),
        )?;

        let mut events = Events::with_capacity(10);
        poll.poll(&mut events, timeout)?;
        if events.is_empty() {
            // timeout
            return Err(io::Error::from(io::ErrorKind::TimedOut).into());
        }

        for event in &events {
            if event.token() == Token(0) {
                let readiness: UnixReady = event.readiness().into();
                if readiness.is_hup() {
                    error!("socket hung up");
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
                }
            }
        }

        Ok(())
    }

    pub async fn send<T>(&self, mut msg: T) -> Result<T::Reply>
    where
        T: Message,
    {
        let (req_n_rx, iov) = msg.get_req_info();
        let handle = self.req_handle.lock().await;
        let result = match req_n_rx {
            Some((req, rx)) => {
                let req_tx = &handle.req_tx;
                req_tx.send(req).await;
                Self::request(handle.fd, iov).await?;
                mem::drop(handle);
                match rx.recv().await {
                    Some(v) => v,
                    None => {
                        error!("unable to receive reply for the request");
                        let e = self.err_rx.recv().await;
                        return Err(msg.get_error(e));
                    }
                }
            }
            None => {
                Self::request(handle.fd, iov).await?;
                mem::drop(handle);
                vec![]
            }
        };
        Ok(msg.construct_reply(result))
    }

    pub fn get_uuid(&self) -> &[u8] {
        &self.uuid[..]
    }

    pub fn get_start_time(&self) -> i64 {
        self.start_time
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }
}

lazy_static! {
    static ref EVENT_SZ_MAP: HashMap<u32, usize> = [
        (KVMI_EVENT_BREAKPOINT, size_of::<KvmiEventBreakpoint>()),
        (KVMI_EVENT_CREATE_VCPU, 0),
        (KVMI_EVENT_CR, size_of::<KvmiEventCR>()),
        (KVMI_EVENT_DESCRIPTOR, size_of::<KvmiEventDescriptor>()),
        (KVMI_EVENT_HYPERCALL, 0),
        (KVMI_EVENT_MSR, size_of::<KvmiEventMSR>()),
        (KVMI_EVENT_PAUSE_VCPU, 0),
        (KVMI_EVENT_PF, size_of::<KvmiEventPF>()),
        (KVMI_EVENT_TRAP, size_of::<KvmiEventTrap>()),
        (KVMI_EVENT_SINGLESTEP, size_of::<KvmiEventSingleStep>()),
        (KVMI_EVENT_UNHOOK, 0),
        (KVMI_EVENT_XSETBV, 0),
    ]
    .iter()
    .copied()
    .collect();
}

#[derive(Debug)]
pub struct Event {
    common: KvmiEvent,
    extra: EventExtra,
    seq: u32,
}

impl Event {
    pub fn get_extra(&self) -> &EventExtra {
        &self.extra
    }

    pub fn get_vcpu(&self) -> u16 {
        self.common.0.vcpu
    }

    pub fn get_arch(&self) -> &kvmi_event_arch {
        &self.common.0.arch
    }
}

#[derive(Debug)]
pub enum EventExtra {
    CR(Box<KvmiEventCR>),
    MSR(Box<KvmiEventMSR>),
    Breakpoint(Box<KvmiEventBreakpoint>),
    PF(Box<KvmiEventPF>),
    Trap(Box<KvmiEventTrap>),
    Descriptor(Box<KvmiEventDescriptor>),
    SingleStep(Box<KvmiEventSingleStep>),
    CreateVCPU,
    HyperCall,
    PauseVCPU,
    Unhook,
    XSetBV,
}

fn new_seq() -> u32 {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    SEQ.fetch_add(1, Ordering::Relaxed)
}

// Error handling
#[derive(Debug)]
pub struct Error {
    repr: Repr,
}

impl Error {
    pub fn kind(&self) -> ErrorKind {
        match &self.repr {
            Repr::Simple(kind) => *kind,
            Repr::IO(_) => ErrorKind::IO,
            Repr::Custom(w) => w.kind,
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ErrorKind {
    FlagNSig,
    IO,
    MalStr,
    HandshakeNoData,
    Handshake,
    Handshake2Big,
    UnsupportedOp,
    InvalidPath,
    UnknownKVMIEvent,
    NeedVCPUNum,
    Parameter,
    MismatchedEventKind,
}

#[derive(Debug)]
enum Repr {
    IO(io::Error),
    Simple(ErrorKind),
    Custom(Wrapper),
}

#[derive(Debug)]
struct Wrapper {
    kind: ErrorKind,
    error: Box<dyn error::Error + Send + Sync>,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Simple(ref kind) => match kind {
                ErrorKind::Handshake => write!(f, "handshake rejected"),
                ErrorKind::HandshakeNoData => write!(f, "too little handshake data"),
                ErrorKind::Handshake2Big => write!(f, "too much handshake data"),
                ErrorKind::FlagNSig => write!(f, "cannot set MSG_NOSIGNAL flag"),
                ErrorKind::UnknownKVMIEvent => write!(f, "unknown KVMI event"),
                ErrorKind::UnsupportedOp => write!(f, "unsupported operation/command"),
                ErrorKind::Parameter => write!(f, "wrong parameter"),
                _ => write!(f, "{:?}", self),
            },
            Repr::IO(e) => write!(f, "failed to do io: {}", e),
            Repr::Custom(ref w) => match w.kind {
                ErrorKind::MalStr => write!(f, "malformed string data: {:?}", w.error),
                ErrorKind::UnsupportedOp => write!(f, "unsupported operation: {:?}", w.error),
                ErrorKind::InvalidPath => write!(f, "invalid path: {:?}", w.error),
                _ => write!(f, "{:?}", self),
            },
        }
    }
}

impl Error {
    fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
    {
        Self {
            repr: Repr::Custom(Wrapper {
                kind,
                error: error.into(),
            }),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            repr: Repr::Simple(kind),
        }
    }
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error { repr: Repr::IO(e) }
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        Self::new(ErrorKind::MalStr, e)
    }
}

impl From<FromBytesWithNulError> for Error {
    fn from(e: FromBytesWithNulError) -> Self {
        Self::new(ErrorKind::MalStr, e)
    }
}

impl From<nix::Error> for Error {
    fn from(e: nix::Error) -> Self {
        match e {
            nix::Error::Sys(errno) => io::Error::from_raw_os_error(errno as i32).into(),
            nix::Error::InvalidPath => Self::new(ErrorKind::InvalidPath, e),
            nix::Error::InvalidUtf8 => Self::new(ErrorKind::MalStr, e),
            nix::Error::UnsupportedOperation => Self::new(ErrorKind::UnsupportedOp, e),
        }
    }
}
impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use ErrorKind::*;
        match e.repr {
            Repr::IO(ref io_err) => io::Error::new(io_err.kind(), e),
            Repr::Simple(simple) => {
                let kind = match simple {
                    UnknownKVMIEvent | Handshake | Handshake2Big | HandshakeNoData => {
                        io::ErrorKind::InvalidData
                    }
                    Parameter => io::ErrorKind::InvalidInput,
                    _ => io::ErrorKind::Other,
                };
                io::Error::new(kind, e)
            }
            Repr::Custom(_) => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

impl ErrorCode {
    pub fn as_os_error(self) -> libc::c_int {
        match (-self.err) as u32 {
            KVM_ENOSYS => libc::ENOSYS,
            KVM_EFAULT => libc::EFAULT,
            KVM_E2BIG => libc::E2BIG,
            KVM_EPERM => libc::EPERM,
            KVM_EOPNOTSUPP => libc::EOPNOTSUPP,
            KVM_EAGAIN => libc::EAGAIN,
            KVM_EBUSY => libc::EBUSY,
            KVM_EINVAL => libc::EINVAL,
            KVM_ENOENT => libc::ENOENT,
            KVM_ENOMEM => libc::ENOMEM,
            _ => libc::EPROTO,
        }
    }
}
