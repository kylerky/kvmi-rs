use std::cmp;
use std::collections::HashMap;
use std::convert::TryInto;
use std::error;
use std::ffi::{CStr, FromBytesWithNulError};
use std::fmt::{self, Display, Formatter};
use std::io;
use std::marker::Unpin;
use std::mem::{size_of, transmute};
use std::str::Utf8Error;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_std::io::prelude::*;
use async_std::io::BufReader;
use async_std::os::unix::io::{AsRawFd, RawFd};
use async_std::task;

use futures::channel::mpsc as mpsc_fut;
use futures::channel::oneshot;
use futures::{SinkExt, StreamExt};

use log::{debug, error};

use nix::errno::Errno;
use nix::sys::socket::{self, MsgFlags};
use nix::sys::uio::IoVec;

use mio::unix::{EventedFd, UnixReady};
use mio::{Events, Poll, PollOpt, Ready, Token};

#[macro_use]
extern crate lazy_static;

mod c_ffi;
use c_ffi::*;
pub use c_ffi::{
    kvmi_event_arch, kvmi_event_pf, HSToWire, KvmiEventCR, KvmiEventPF, PageAccessEntry,
};

mod utils;
use utils::*;

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
    pub async fn handshake<F>(self, validate: F) -> Result<(Domain, mpsc_fut::Receiver<Event>)>
    where
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let mut reader = self.reader;
        let (name, uuid, start_time) = Self::read_handshake_data(&mut reader).await?;

        let fd = self.fd;

        let (event_tx, event_rx) = mpsc_fut::channel(5);
        let (req_tx, req_rx) = mpsc_fut::channel(1);
        let deserializer = task::spawn(Self::deserializer(reader, event_tx, req_rx));

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
                fd,
                req_tx,
                deser_handle: Some(deserializer),
                vcpu_num: 0,
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
        mut reader: BufReader<T>,
        mut event_tx: mpsc_fut::Sender<Event>,
        mut req_rx: mpsc_fut::Receiver<Request>,
    ) -> Result<()> {
        loop {
            let header = Self::recv_header(&mut reader).await?;
            match header.id as u32 {
                KVMI_EVENT => Self::recv_event(&mut reader, &mut event_tx, &header).await?,
                _ => Self::recv_reply(&mut reader, &mut req_rx, &header).await?,
            }
        }
    }

    async fn recv_reply(
        mut reader: &mut BufReader<T>,
        req_rx: &mut mpsc_fut::Receiver<Request>,
        header: &MsgHeader,
    ) -> Result<()> {
        let req = match req_rx.next().await {
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

        match req.result.send(buffer) {
            Err(_) => {
                error!("failed to send result through oneshot channel");
                Err(io::Error::new(io::ErrorKind::WriteZero, "Cannot write the result").into())
            }
            _ => Ok(()),
        }
    }

    const KVMI_MSG_SZ: usize = 4096 - 8;
    async fn recv_event(
        reader: &mut BufReader<T>,
        event_tx: &mut mpsc_fut::Sender<Event>,
        header: &MsgHeader,
    ) -> Result<()> {
        if header.size as usize > Self::KVMI_MSG_SZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The KVMI message to receive is too big",
            )
            .into());
        }

        let mut buffer = Vec::with_capacity(header.size as usize);
        buffer.resize(header.size as usize, 0u8);
        reader.read_exact(&mut buffer[..]).await?;

        let event = Self::construct_event(buffer, header.seq)?;
        match event_tx.send(event).await {
            Err(e) => {
                error!("failed to send result through event channel");
                return Err(e.into());
            }
            _ => (),
        }

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
            let mut buf = Vec::with_capacity(sz);
            buf.resize(sz, 0u8);
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
                KVMI_EVENT_CREATE_VCPU => EventExtra::CreateVCPU,
                KVMI_EVENT_HYPERCALL => EventExtra::HyperCall,
                KVMI_EVENT_PAUSE_VCPU => EventExtra::PauseVCPU,
                KVMI_EVENT_UNHOOK => EventExtra::Unhook,
                KVMI_EVENT_XSETBV => EventExtra::XSetBV,
                KVMI_EVENT_SINGLESTEP => EventExtra::SingleStep,
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
        let mut buffer = Vec::with_capacity(type_size);
        buffer.resize(type_size, 0);

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
    vcpu_num: u32,
    fd: RawFd,
    req_tx: mpsc_fut::Sender<Request>,
    deser_handle: Option<task::JoinHandle<Result<()>>>,
}

#[derive(Debug)]
struct Request {
    size: usize,
    kind: u16,
    seq: u32,
    result: oneshot::Sender<Vec<u8>>,
}

type PFReply = kvmi_event_pf_reply;

pub enum EventReplyReqExtra {
    CR(u64),
    MSR(u64),
    PF(Option<VecBuf<PFReply>>),
}

impl EventReplyReqExtra {
    pub fn new_pf_extra() -> Self {
        Self::PF(Some(VecBuf::<PFReply>::new()))
    }

    pub fn new_cr_extra(cr: u64) -> Self {
        Self::CR(cr)
    }
}

pub struct EventReplyReq {
    vcpu: u16,
    event: u8,
    seq: u32,
    action: Action,
    extra: Option<EventReplyReqExtra>,
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

    async fn send_and_get(&mut self, mut msg: Message) -> Result<Option<Reply>> {
        use Message::*;
        let (req, rx, iov) = self.get_req_info(&mut msg)?;

        let req_tx = &mut self.req_tx;

        let result = match req_tx.send(req).await {
            Ok(_) => {
                Self::request(self.fd, iov).await?;
                let result = rx.await?;
                result.into_boxed_slice()
            }
            Err(e) => {
                error!("unable to send request through the request channel");
                if let Some(handle) = self.deser_handle.take() {
                    handle.await?;
                }
                return Err(e.into());
            }
        };

        match msg {
            GetVersion => {
                let result: Box<kvmi_get_version_reply> = unsafe { boxed_slice_to_type(result) };
                Ok(Some(Reply::Version(result.version)))
            }
            GetMaxGfn => {
                let result: Box<kvmi_get_max_gfn_reply> = unsafe { boxed_slice_to_type(result) };
                Ok(Some(Reply::MaxGfn(result.gfn)))
            }
            GetVCPUNum => {
                let result: Box<kvmi_get_guest_info_reply> = unsafe { boxed_slice_to_type(result) };
                self.vcpu_num = result.vcpu_count;
                Ok(Some(Reply::VCPUNum(result.vcpu_count)))
            }
            PauseAllVCPU | ControlEvent(_, _, _) | SetPageAccess(_) => Ok(None),
            _ => unreachable!(),
        }
    }

    fn get_req_info(
        &self,
        msg: &mut Message,
    ) -> Result<(Request, oneshot::Receiver<Vec<u8>>, Vec<Vec<u8>>)> {
        use Message::*;
        let (reply_sz, kind) = match msg {
            GetVersion => (size_of::<kvmi_get_version_reply>(), KVMI_GET_VERSION),
            GetMaxGfn => (size_of::<kvmi_get_max_gfn_reply>(), KVMI_GET_MAX_GFN),
            GetVCPUNum => (size_of::<kvmi_get_guest_info_reply>(), KVMI_GET_GUEST_INFO),
            ControlEvent(_, _, _) => (0, KVMI_CONTROL_EVENTS),
            PauseAllVCPU => (0, KVMI_CONTROL_CMD_RESPONSE),
            SetPageAccess(_) => (0, KVMI_SET_PAGE_ACCESS),
            _ => unreachable!(),
        };

        let (iov, seq) = match msg {
            GetVersion | GetMaxGfn | GetVCPUNum => {
                let seq = new_seq();
                let hdr = Self::get_header(kind as u16, 0, seq);
                (vec![hdr.into()], seq)
            }
            ControlEvent(vcpu, event, enable) => {
                Self::get_control_events_iov(*vcpu, *event as u16, *enable)
            }
            PauseAllVCPU => Self::get_vcpu_pause_iov(self.vcpu_num),
            SetPageAccess(entries) => match entries.take() {
                Some(entries) => Self::get_set_page_access_iov(entries),
                None => return Err(Error::from(ErrorKind::Parameter)),
            },
            _ => unreachable!(),
        };

        let (tx, rx) = oneshot::channel();
        let req = Request {
            size: reply_sz,
            kind: kind as u16,
            seq,
            result: tx,
        };

        Ok((req, rx, iov))
    }

    fn get_set_page_access_iov(entries: Vec<PageAccessEntry>) -> (Vec<Vec<u8>>, u32) {
        let entries_len = entries.len();

        let msg_sz = size_of::<kvmi_set_page_access>() + entries_len * size_of::<PageAccessEntry>();
        let seq = new_seq();
        let hdr = Self::get_header(KVMI_SET_PAGE_ACCESS as u16, msg_sz as u16, seq);

        let mut msg = VecBuf::<kvmi_set_page_access>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.count = entries_len as u16;
        }

        let entries = any_vec_as_u8_vec(entries);
        (vec![hdr.into(), msg.into(), entries], seq)
    }

    fn get_control_events_iov(vcpu: u16, event: u16, enable: bool) -> (Vec<Vec<u8>>, u32) {
        let seq = new_seq();
        let hdr = Self::get_header(
            KVMI_CONTROL_EVENTS as u16,
            size_of::<ControlEventsMsg>() as u16,
            seq,
        );

        let mut msg = VecBuf::<ControlEventsMsg>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.hdr.vcpu = vcpu;
            typed.cmd.event_id = event;
            typed.cmd.enable = enable as u8;
        }

        (vec![hdr.into(), msg.into()], seq)
    }

    fn get_vcpu_pause_iov(vcpu_num: u32) -> (Vec<Vec<u8>>, u32) {
        let (prefix, _) = Self::get_control_cmd_response_vec(0, 1);

        let mut pause_msgs = VecBuf::<PauseVCPUMsg>::new_array(vcpu_num as usize);
        for i in 0..vcpu_num as usize {
            unsafe {
                let msg = pause_msgs.nth_as_mut_type(i);
                msg.hdr.id = KVMI_PAUSE_VCPU as u16;
                msg.hdr.seq = new_seq();
                msg.hdr.size = (size_of::<kvmi_vcpu_hdr>() + size_of::<kvmi_pause_vcpu>()) as u16;

                msg.vcpu_hdr.vcpu = i as u16;

                msg.cmd.wait = 1;
            }
        }

        let (suffix, seq) = Self::get_control_cmd_response_vec(1, 1);

        (vec![prefix.into(), pause_msgs.into(), suffix.into()], seq)
    }

    fn get_control_cmd_response_vec(enable: u8, now: u8) -> (VecBuf<ControlCmdRespMsg>, u32) {
        let seq = new_seq();
        let mut buf = VecBuf::<ControlCmdRespMsg>::new();
        unsafe {
            let msg = buf.as_mut_type();
            msg.hdr.id = KVMI_CONTROL_CMD_RESPONSE as u16;
            msg.hdr.seq = seq;
            msg.hdr.size = size_of::<kvmi_control_cmd_response>() as u16;
            msg.cmd.enable = enable;
            msg.cmd.now = now;
        }
        (buf, seq)
    }

    async fn send_with(&mut self, msg: Message) -> Result<Option<Reply>> {
        let (mut vec, kind, seq) = match msg {
            Message::EventReply(reply_req) => {
                let (reply_iov, seq) = Self::get_reply_info(reply_req);
                (reply_iov, KVMI_EVENT_REPLY, seq)
            }
            _ => unreachable!(),
        };
        let hdr = Self::get_header(
            kind as u16,
            vec.iter().map(|v| v.len()).sum::<usize>() as u16,
            seq,
        );

        let mut iov: Vec<Vec<u8>> = vec![hdr.into()];
        iov.append(&mut vec);
        Self::request(self.fd, iov).await.map(|_| None)
    }

    fn get_header(kind: u16, size: u16, seq: u32) -> VecBuf<MsgHeader> {
        let mut hdr = VecBuf::<MsgHeader>::new();
        unsafe {
            let hdr_ref = hdr.as_mut_type();
            hdr_ref.id = kind;
            hdr_ref.size = size;
            hdr_ref.seq = seq;
        }
        hdr
    }

    fn get_reply_info(reply_req: EventReplyReq) -> (Vec<Vec<u8>>, u32) {
        let (vcpu, event, extra, seq, action) = match reply_req {
            EventReplyReq {
                vcpu,
                event,
                extra: Some(req),
                seq,
                action,
            } => {
                let extra = Self::get_reply_info_extra(req);
                (vcpu, event, Some(extra), seq, action)
            }
            EventReplyReq {
                vcpu,
                event,
                extra: None,
                seq,
                action,
            } => (vcpu, event, None, seq, action),
        };

        let mut reply = VecBuf::<EventReply>::new();
        unsafe {
            *reply.as_mut_type() = EventReply {
                hdr: kvmi_vcpu_hdr {
                    vcpu,
                    padding1: 0,
                    padding2: 0,
                },
                common: kvmi_event_reply {
                    action: action as u8,
                    event,
                    padding1: 0,
                    padding2: 0,
                },
            };
        }
        let iov = match extra {
            Some(extra) => vec![reply.into(), extra],
            None => vec![reply.into()],
        };
        (iov, seq)
    }

    fn get_reply_info_extra(req: EventReplyReqExtra) -> Vec<u8> {
        use EventReplyReqExtra::*;
        match req {
            CR(new_val) => {
                let mut buf = VecBuf::<kvmi_event_cr_reply>::new();
                unsafe {
                    buf.as_mut_type().new_val = new_val;
                }
                buf.into()
            }
            MSR(new_val) => {
                let mut buf = VecBuf::<kvmi_event_msr_reply>::new();
                unsafe {
                    buf.as_mut_type().new_val = new_val;
                }
                buf.into()
            }
            PF(mut reply) => {
                let buf = reply.take().unwrap();
                buf.into()
            }
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<Option<Reply>> {
        use Message::*;
        match msg {
            GetMaxGfn | GetVersion | GetVCPUNum | ControlEvent(_, _, _) | SetPageAccess(_) => {
                self.send_and_get(msg).await
            }
            EventReply(_) => self.send_with(msg).await,
            PauseAllVCPU => {
                if self.vcpu_num == 0 {
                    return Err(Error::from(ErrorKind::NeedVCPUNum));
                }
                self.send_and_get(msg).await
            }
        }
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
        (KVMI_EVENT_UNHOOK, 0),
        (KVMI_EVENT_XSETBV, 0),
        (KVMI_EVENT_SINGLESTEP, 0),
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

    pub fn get_arch(&self) -> kvmi_event_arch {
        self.common.0.arch
    }

    pub fn new_reply(
        &self,
        action: Action,
        extra: Option<EventReplyReqExtra>,
    ) -> Result<EventReplyReq> {
        let ok = match self.extra {
            EventExtra::CR(_) => match extra {
                Some(EventReplyReqExtra::CR(_)) => true,
                _ => false,
            },
            EventExtra::MSR(_) => match extra {
                Some(EventReplyReqExtra::MSR(_)) => true,
                _ => false,
            },
            EventExtra::PF(_) => match extra {
                Some(EventReplyReqExtra::PF(_)) => true,
                _ => false,
            },
            _ => match extra {
                None => true,
                _ => false,
            },
        };

        if !ok {
            return Err(Error::from(ErrorKind::MismatchedEventKind));
        }

        Ok(EventReplyReq {
            vcpu: self.common.0.vcpu,
            event: self.common.0.event,
            seq: self.seq,
            action,
            extra,
        })
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
    CreateVCPU,
    HyperCall,
    PauseVCPU,
    Unhook,
    XSetBV,
    SingleStep,
}

pub enum Reply {
    Version(u32),
    MaxGfn(u64),
    VCPUNum(u32),
}

pub enum Message {
    GetVersion,
    GetMaxGfn,
    GetVCPUNum,
    PauseAllVCPU,
    EventReply(EventReplyReq),
    ControlEvent(u16, EventKind, bool),
    SetPageAccess(Option<Vec<PageAccessEntry>>),
}

unsafe fn boxed_slice_to_type<T, O>(s: Box<[T]>) -> Box<O> {
    let p = Box::into_raw(s) as *mut O;
    Box::from_raw(p)
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

impl From<mpsc_fut::SendError> for Error {
    fn from(e: mpsc_fut::SendError) -> Self {
        io::Error::new(io::ErrorKind::WriteZero, e).into()
    }
}

impl From<oneshot::Canceled> for Error {
    fn from(e: oneshot::Canceled) -> Self {
        io::Error::new(io::ErrorKind::UnexpectedEof, e).into()
    }
}

impl ErrorCode {
    pub fn as_os_error(&self) -> libc::c_int {
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
