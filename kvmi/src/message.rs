use crate::utils::*;
use crate::*;

pub(super) use opaque::*;
mod opaque {
    use crate::*;
    pub trait Msg {
        fn get_req_info(&mut self)
            -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>);
        fn construct_reply(&self, result: Box<[u8]>) -> Option<Reply>;
    }

    #[derive(Debug)]
    pub struct Request {
        pub size: usize,
        pub kind: u16,
        pub seq: u32,
        pub result: oneshot::Sender<Vec<u8>>,
    }
}

pub trait Message: Msg {}

fn get_request(kind: u16, size: usize, seq: u32) -> (Request, oneshot::Receiver<Vec<u8>>) {
    let (tx, rx) = oneshot::channel();
    (
        Request {
            size,
            kind: kind as u16,
            seq,
            result: tx,
        },
        rx,
    )
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

pub struct GetMaxGfn;
impl Message for GetMaxGfn {}
impl Msg for GetMaxGfn {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_GET_MAX_GFN as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_get_max_gfn_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn construct_reply(&self, result: Box<[u8]>) -> Option<Reply> {
        let result: Box<kvmi_get_max_gfn_reply> = unsafe { boxed_slice_to_type(result) };
        Some(Reply::MaxGfn(result.gfn))
    }
}
impl GetMaxGfn {
    pub fn new() -> Self {
        Self
    }
}

pub struct GetVersion;
impl Message for GetVersion {}
impl Msg for GetVersion {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_GET_VERSION as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_get_version_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn construct_reply(&self, result: Box<[u8]>) -> Option<Reply> {
        let result: Box<kvmi_get_version_reply> = unsafe { boxed_slice_to_type(result) };
        Some(Reply::Version(result.version))
    }
}
impl GetVersion {
    pub fn new() -> Self {
        Self
    }
}

pub struct GetVCPUNum;
impl Message for GetVCPUNum {}
impl Msg for GetVCPUNum {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_GET_GUEST_INFO as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_get_guest_info_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn construct_reply(&self, result: Box<[u8]>) -> Option<Reply> {
        let result: Box<kvmi_get_guest_info_reply> = unsafe { boxed_slice_to_type(result) };
        Some(Reply::VCPUNum(result.vcpu_count))
    }
}
impl GetVCPUNum {
    pub fn new() -> Self {
        Self
    }
}

pub struct ControlEvent {
    vcpu: u16,
    event: EventKind,
    enable: bool,
}
impl Message for ControlEvent {}
impl Msg for ControlEvent {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_CONTROL_EVENTS as u16;
        let hdr = get_header(kind, size_of::<ControlEventsMsg>() as u16, seq);

        let mut msg = VecBuf::<ControlEventsMsg>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.hdr.vcpu = self.vcpu;
            typed.cmd.event_id = self.event as u16;
            typed.cmd.enable = self.enable as u8;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into()])
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl ControlEvent {
    pub fn new(vcpu: u16, event: EventKind, enable: bool) -> Self {
        Self {
            vcpu,
            event,
            enable,
        }
    }
}

pub struct ControlCR {
    vcpu: u16,
    cr: u32,
    enable: bool,
}
impl Message for ControlCR {}
impl Msg for ControlCR {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_CONTROL_CR as u16;
        let hdr = get_header(kind, size_of::<ControlCRMsg>() as u16, seq);

        let mut msg = VecBuf::<ControlCRMsg>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.hdr.vcpu = self.vcpu;
            typed.cmd.cr = self.cr;
            typed.cmd.enable = self.enable as u8;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into()])
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl ControlCR {
    pub fn new(vcpu: u16, cr: u32, enable: bool) -> Self {
        Self { vcpu, cr, enable }
    }
}

pub struct PauseVCPUs {
    num: u32,
}
impl Message for PauseVCPUs {}
impl Msg for PauseVCPUs {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let (prefix, _) = get_control_cmd_response_vec(0, 1);

        let vcpu_num = self.num;
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

        let (suffix, seq) = get_control_cmd_response_vec(1, 1);

        let req_n_rx = get_request(KVMI_CONTROL_CMD_RESPONSE as u16, 0, seq);
        (
            Some(req_n_rx),
            vec![prefix.into(), pause_msgs.into(), suffix.into()],
        )
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
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
impl PauseVCPUs {
    pub fn new(num: u32) -> Option<Self> {
        if num == 0 {
            return None;
        }
        Some(Self { num })
    }
}

pub struct SetPageAccess {
    entries: Option<Vec<PageAccessEntry>>,
}
impl Message for SetPageAccess {}
impl Msg for SetPageAccess {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let kind = KVMI_SET_PAGE_ACCESS as u16;
        let entries = self.entries.take().unwrap();
        let entries_len = entries.len();

        let msg_sz = size_of::<kvmi_set_page_access>() + entries_len * size_of::<PageAccessEntry>();
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);

        let mut msg = VecBuf::<kvmi_set_page_access>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.count = entries_len as u16;
        }

        let entries = any_vec_as_u8_vec(entries);

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into(), entries])
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl SetPageAccess {
    pub fn new() -> Self {
        Self {
            entries: Some(vec![]),
        }
    }

    pub fn push(&mut self, entry: PageAccessEntry) {
        if let Some(entries) = self.entries.as_mut() {
            entries.push(entry);
        }
    }
}

pub struct CommonEventReply {
    buf: Option<VecBuf<EventReply>>,
    seq: u32,
}
impl Message for CommonEventReply {}
impl Msg for CommonEventReply {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let kind = KVMI_EVENT_REPLY as u16;
        let sz = size_of::<EventReply>() as u16;
        let seq = self.seq;
        let hdr = get_header(kind, sz, seq);
        (None, vec![hdr.into(), self.buf.take().unwrap().into()])
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl CommonEventReply {
    pub fn new(event: &Event, action: Action) -> Option<Self> {
        use EventExtra::*;
        match event.get_extra() {
            CR(_) | MSR(_) | PF(_) => return None,
            _ => (),
        }
        let buf = get_event_reply_buf(event, action);
        Some(Self {
            buf: Some(buf),
            seq: event.seq,
        })
    }
}
pub fn get_event_reply_buf(event: &Event, action: Action) -> VecBuf<EventReply> {
    let mut buf = VecBuf::<EventReply>::new();
    unsafe {
        let typed = buf.as_mut_type();
        typed.hdr.vcpu = event.get_vcpu();
        typed.common.action = action as u8;
        typed.common.event = event.common.0.event;
    }
    buf
}

pub struct CREventReply {
    common: Option<VecBuf<EventReply>>,
    cr: Option<VecBuf<kvmi_event_cr_reply>>,
    seq: u32,
}
impl Message for CREventReply {}
impl Msg for CREventReply {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let kind = KVMI_EVENT_REPLY as u16;
        let sz = (size_of::<EventReply>() + size_of::<kvmi_event_cr_reply>()) as u16;
        let hdr = get_header(kind, sz, self.seq);
        (
            None,
            vec![
                hdr.into(),
                self.common.take().unwrap().into(),
                self.cr.take().unwrap().into(),
            ],
        )
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl CREventReply {
    pub fn new(event: &Event, action: Action, new_val: u64) -> Option<Self> {
        use EventExtra::*;
        match event.get_extra() {
            CR(_) => (),
            _ => return None,
        }
        let mut cr = VecBuf::<kvmi_event_cr_reply>::new();
        unsafe {
            cr.as_mut_type().new_val = new_val;
        }
        let common = get_event_reply_buf(event, action);
        Some(Self {
            common: Some(common),
            cr: Some(cr),
            seq: event.seq,
        })
    }
}

pub struct MSREventReply {
    common: Option<VecBuf<EventReply>>,
    msr: Option<VecBuf<kvmi_event_msr_reply>>,
    seq: u32,
}
impl Message for MSREventReply {}
impl Msg for MSREventReply {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let kind = KVMI_EVENT_REPLY as u16;
        let sz = (size_of::<EventReply>() + size_of::<kvmi_event_msr_reply>()) as u16;
        let hdr = get_header(kind, sz, self.seq);
        (
            None,
            vec![
                hdr.into(),
                self.common.take().unwrap().into(),
                self.msr.take().unwrap().into(),
            ],
        )
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl MSREventReply {
    pub fn new(event: &Event, action: Action, new_val: u64) -> Option<Self> {
        use EventExtra::*;
        match event.get_extra() {
            MSR(_) => (),
            _ => return None,
        }
        let mut msr = VecBuf::<kvmi_event_msr_reply>::new();
        unsafe {
            msr.as_mut_type().new_val = new_val;
        }
        let common = get_event_reply_buf(event, action);
        Some(Self {
            common: Some(common),
            msr: Some(msr),
            seq: event.seq,
        })
    }
}

pub struct PFEventReply {
    common: Option<VecBuf<EventReply>>,
    pf: Option<VecBuf<kvmi_event_pf_reply>>,
    seq: u32,
}
impl Message for PFEventReply {}
impl Msg for PFEventReply {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>) {
        let kind = KVMI_EVENT_REPLY as u16;
        let sz = (size_of::<EventReply>() + size_of::<kvmi_event_pf_reply>()) as u16;
        let hdr = get_header(kind, sz, self.seq);
        (
            None,
            vec![
                hdr.into(),
                self.common.take().unwrap().into(),
                self.pf.take().unwrap().into(),
            ],
        )
    }
    fn construct_reply(&self, _result: Box<[u8]>) -> Option<Reply> {
        None
    }
}
impl PFEventReply {
    pub fn new(event: &Event, action: Action) -> Option<Self> {
        use EventExtra::*;
        match event.get_extra() {
            PF(_) => (),
            _ => return None,
        }
        let pf = VecBuf::<kvmi_event_pf_reply>::new();
        let common = get_event_reply_buf(event, action);
        Some(Self {
            common: Some(common),
            pf: Some(pf),
            seq: event.seq,
        })
    }
}