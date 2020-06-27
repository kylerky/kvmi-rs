use log::warn;

use crate::utils::*;
use crate::*;

pub(super) use opaque::*;
mod opaque;

use std::io;

pub trait Messenger {
    type Reply;
}
pub trait Message: Msg {}

#[cfg(test)]
mod tests;

type ReqHandle = (Request, sync::Receiver<Vec<u8>>);

fn get_request(kind: u16, size: usize, seq: u32) -> ReqHandle {
    let (tx, rx) = sync::channel(1);
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

#[derive(Default)]
pub struct GetMaxGfn;
impl Message for GetMaxGfn {}
impl Messenger for GetMaxGfn {
    type Reply = u64;
}
impl Msg for GetMaxGfn {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_VM_GET_MAX_GFN as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_vm_get_max_gfn_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error getting max gfn").into()
    }
    fn construct_reply(&self, result: Vec<u8>) -> Self::Reply {
        let result: Box<kvmi_vm_get_max_gfn_reply> =
            unsafe { boxed_slice_to_type(result.into_boxed_slice()) };
        result.gfn
    }
}

#[derive(Default)]
pub struct GetVersion;
impl Message for GetVersion {}
impl Messenger for GetVersion {
    type Reply = u32;
}
impl Msg for GetVersion {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_GET_VERSION as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_get_version_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error getting KVMI version").into()
    }
    fn construct_reply(&self, result: Vec<u8>) -> Self::Reply {
        let result: Box<kvmi_get_version_reply> =
            unsafe { boxed_slice_to_type(result.into_boxed_slice()) };
        result.version
    }
}

#[derive(Default)]
pub struct GetVCPUNum;
impl Message for GetVCPUNum {}
impl Messenger for GetVCPUNum {
    type Reply = u32;
}
impl Msg for GetVCPUNum {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_VM_GET_INFO as u16;
        let hdr = get_header(kind, 0, seq);
        let req_n_rx = get_request(kind, size_of::<kvmi_vm_get_info_reply>(), seq);
        (Some(req_n_rx), vec![hdr.into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Error getting the number of VCPU",
        )
        .into()
    }
    fn construct_reply(&self, result: Vec<u8>) -> Self::Reply {
        let result: Box<kvmi_vm_get_info_reply> =
            unsafe { boxed_slice_to_type(result.into_boxed_slice()) };
        result.vcpu_count
    }
}
impl GetVCPUNum {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, PartialEq)]
pub struct GetRegistersReply {
    data: Box<[u8]>,
}
impl GetRegistersReply {
    pub fn get_regs(&self) -> &kvmi_vcpu_get_registers_reply {
        unsafe { &*self.data.as_ptr().cast() }
    }

    /// # Safety
    ///
    /// msrs.nmsrs and msrs.entries should not be mutated.
    /// Otherwise, it will cause undefined behaviours.
    pub unsafe fn get_regs_mut(&mut self) -> &mut kvmi_vcpu_get_registers_reply {
        &mut *self.data.as_mut_ptr().cast()
    }

    pub fn get_msrs(&self) -> &[kvm_msr_entry] {
        let ptr = self.data.as_ptr().cast::<kvmi_vcpu_get_registers_reply>();
        unsafe {
            let reply = ptr.as_ref().unwrap();
            let nmsrs = reply.msrs.nmsrs as usize;
            reply.msrs.entries.as_slice(nmsrs)
        }
    }
}
impl Default for GetRegistersReply {
    fn default() -> Self {
        Self {
            data: vec![0u8; size_of::<kvmi_vcpu_get_registers_reply>()].into_boxed_slice(),
        }
    }
}

pub struct GetRegisters {
    vcpu: u16,
    msrs: Option<Vec<u32>>,
}
impl Message for GetRegisters {}
impl Messenger for GetRegisters {
    type Reply = GetRegistersReply;
}
impl Msg for GetRegisters {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_VCPU_GET_REGISTERS as u16;

        let msrs = self.msrs.take().unwrap();
        let nmsrs = msrs.len();
        let msg_sz = size_of::<kvmi_vcpu_hdr>()
            + size_of::<kvmi_vcpu_get_registers>()
            + size_of::<u32>() * nmsrs;
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);

        let mut vcpu_msg = VecBuf::<kvmi_vcpu_hdr>::new();
        unsafe {
            let typed = vcpu_msg.as_mut_type();
            typed.vcpu = self.vcpu;
        }

        let mut reg_msg = VecBuf::<kvmi_vcpu_get_registers>::new();
        unsafe {
            let typed = reg_msg.as_mut_type();
            typed.nmsrs = nmsrs as u16;
        }

        let msrs = any_vec_as_u8_vec(msrs);

        let req_n_rx = get_request(
            kind,
            size_of::<kvmi_vcpu_get_registers_reply>() + nmsrs * size_of::<kvm_msr_entry>(),
            seq,
        );
        (
            Some(req_n_rx),
            vec![hdr.into(), vcpu_msg.into(), reg_msg.into(), msrs],
        )
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error getting the registers").into()
    }
    fn construct_reply(&self, mut result: Vec<u8>) -> Self::Reply {
        let ptr = result.as_ptr().cast::<kvmi_vcpu_get_registers_reply>();

        let regs_sz = size_of::<kvmi_vcpu_get_registers_reply>();
        let data_len = result.len();
        let nmsrs = unsafe { ptr.as_ref().unwrap().msrs.nmsrs as usize };
        let entry_sz = size_of::<kvm_msr_entry>();
        let expected = regs_sz + nmsrs * entry_sz;
        if expected != data_len {
            warn!("Mismatched KVMI_GET_REGISTERS_REPLY\nExpected: {} Received: {}\nThrowing away MSR data", expected, data_len);
            result.resize(regs_sz, 0u8);
            let ptr = result.as_mut_ptr().cast::<kvmi_vcpu_get_registers_reply>();
            unsafe {
                ptr.as_mut().unwrap().msrs.nmsrs = 0;
            }
        }
        GetRegistersReply {
            data: result.into_boxed_slice(),
        }
    }
}
impl GetRegisters {
    pub fn new(vcpu: u16, msrs: Vec<u32>) -> Self {
        Self {
            vcpu,
            msrs: Some(msrs),
        }
    }
}

pub struct SetRegisters {
    vcpu: u16,
    regs: Option<VecBuf<kvm_regs>>,
}
impl Message for SetRegisters {}
impl Messenger for SetRegisters {
    type Reply = ();
}
impl Msg for SetRegisters {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_VCPU_SET_REGISTERS as u16;
        let msg_sz = size_of::<kvmi_vcpu_hdr>() + size_of::<kvm_regs>();
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);
        let regs = self.regs.take().unwrap();

        let mut vcpu_msg = VecBuf::<kvmi_vcpu_hdr>::new();
        unsafe {
            let typed = vcpu_msg.as_mut_type();
            typed.vcpu = self.vcpu;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (
            Some(req_n_rx),
            vec![hdr.into(), vcpu_msg.into(), regs.into()],
        )
    }

    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error setting registers").into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
impl SetRegisters {
    pub fn new(vcpu: u16, regs: &kvm_regs) -> Self {
        let mut regs_buf = VecBuf::<kvm_regs>::new();
        unsafe {
            *regs_buf.as_mut_type() = *regs;
        }
        Self {
            vcpu,
            regs: Some(regs_buf),
        }
    }
}

#[derive(Debug)]
pub struct VcpuControlEvent {
    vcpu: u16,
    event: EventKind,
    enable: bool,
}
impl Message for VcpuControlEvent {}
impl Messenger for VcpuControlEvent {
    type Reply = ();
}
impl Msg for VcpuControlEvent {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_VCPU_CONTROL_EVENTS as u16;
        let hdr = get_header(kind, size_of::<VcpuControlEventsMsg>() as u16, seq);

        let mut msg = VecBuf::<VcpuControlEventsMsg>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.hdr.vcpu = self.vcpu;
            typed.cmd.event_id = self.event as u16;
            typed.cmd.enable = self.enable as u8;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error sending VcpuControlEvent command: {:?}", self),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
impl VcpuControlEvent {
    pub fn new(vcpu: u16, event: EventKind, enable: bool) -> Self {
        Self {
            vcpu,
            event,
            enable,
        }
    }
}

#[derive(Debug)]
pub struct ControlCR {
    vcpu: u16,
    cr: u32,
    enable: bool,
}
impl Message for ControlCR {}
impl Messenger for ControlCR {
    type Reply = ();
}
impl Msg for ControlCR {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_VCPU_CONTROL_CR as u16;
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
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error sending ControlCR command: {:?}", self),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
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
impl Messenger for PauseVCPUs {
    type Reply = ();
}
impl Msg for PauseVCPUs {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let (prefix, _) = get_control_cmd_response_vec(0, 1);

        let vcpu_num = self.num;
        let mut pause_msgs = VecBuf::<PauseVCPUMsg>::new_array(vcpu_num as usize);
        for i in 0..vcpu_num as usize {
            unsafe {
                let msg = pause_msgs.nth_as_mut_type(i);
                msg.hdr.id = KVMI_VCPU_PAUSE as u16;
                msg.hdr.seq = new_seq();
                msg.hdr.size = (size_of::<kvmi_vcpu_hdr>() + size_of::<kvmi_vcpu_pause>()) as u16;

                msg.vcpu_hdr.vcpu = i as u16;

                msg.cmd.wait = 1;
            }
        }

        let (suffix, seq) = get_control_cmd_response_vec(1, 1);

        let req_n_rx = get_request(KVMI_VM_CONTROL_CMD_RESPONSE as u16, 0, seq);
        (
            Some(req_n_rx),
            vec![prefix.into(), pause_msgs.into(), suffix.into()],
        )
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!(
                "Error sending PauseVCPUs command, number of VCPU: {}",
                self.num
            ),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
fn get_control_cmd_response_vec(enable: u8, now: u8) -> (VecBuf<ControlCmdRespMsg>, u32) {
    let seq = new_seq();
    let mut buf = VecBuf::<ControlCmdRespMsg>::new();
    unsafe {
        let msg = buf.as_mut_type();
        msg.hdr.id = KVMI_VM_CONTROL_CMD_RESPONSE as u16;
        msg.hdr.seq = seq;
        msg.hdr.size = size_of::<kvmi_vm_control_cmd_response>() as u16;
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

#[derive(Debug, PartialEq)]
pub struct SetPageAccess {
    entries: Option<Vec<PageAccessEntry>>,
}
impl Message for SetPageAccess {}
impl Messenger for SetPageAccess {
    type Reply = ();
}
impl Msg for SetPageAccess {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_VM_SET_PAGE_ACCESS as u16;
        let entries = self.entries.take().unwrap();
        let entries_len = entries.len();

        let msg_sz =
            size_of::<kvmi_vm_set_page_access>() + entries_len * size_of::<PageAccessEntry>();
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);

        let mut msg = VecBuf::<kvmi_vm_set_page_access>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.count = entries_len as u16;
        }

        let entries = any_vec_as_u8_vec(entries);

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into(), entries])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error setting page access: {:?}", self),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
impl SetPageAccess {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entry: PageAccessEntry) {
        if let Some(entries) = self.entries.as_mut() {
            entries.push(entry);
        }
    }
}
impl Default for SetPageAccess {
    fn default() -> Self {
        Self {
            entries: Some(vec![]),
        }
    }
}

pub struct CommonEventReply {
    buf: Option<VecBuf<EventReply>>,
    seq: u32,
}
impl Message for CommonEventReply {}
impl Messenger for CommonEventReply {
    type Reply = ();
}
impl Msg for CommonEventReply {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_EVENT_REPLY as u16;
        let sz = size_of::<EventReply>() as u16;
        let seq = self.seq;
        let hdr = get_header(kind, sz, seq);
        (None, vec![hdr.into(), self.buf.take().unwrap().into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error sending reply to event").into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
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
impl Messenger for CREventReply {
    type Reply = ();
}
impl Msg for CREventReply {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
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
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error sending CREventReply").into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
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
impl Messenger for MSREventReply {
    type Reply = ();
}
impl Msg for MSREventReply {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
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
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error sending MSREventReply").into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
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
impl Messenger for PFEventReply {
    type Reply = ();
}
impl Msg for PFEventReply {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
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
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "Error sending PFEventReply").into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
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

#[derive(Debug, PartialEq, Eq)]
pub struct ReadPhysical {
    gpa: u64,
    size: u64,
}
impl Message for ReadPhysical {}
impl Messenger for ReadPhysical {
    type Reply = Vec<u8>;
}
impl Msg for ReadPhysical {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let seq = new_seq();
        let kind = KVMI_VM_READ_PHYSICAL as u16;
        let hdr = get_header(kind, size_of::<kvmi_vm_read_physical>() as u16, seq);
        let req_n_rx = get_request(kind, self.size as usize, seq);

        let mut buf = VecBuf::<kvmi_vm_read_physical>::new();
        unsafe {
            *buf.as_mut_type() = kvmi_vm_read_physical {
                size: self.size,
                gpa: self.gpa,
            };
        }

        (Some(req_n_rx), vec![hdr.into(), buf.into()])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error reading physical address: 0x{:x?}", self.gpa),
        )
        .into()
    }
    fn construct_reply(&self, result: Vec<u8>) -> Self::Reply {
        result
    }
}
impl ReadPhysical {
    pub fn new(gpa: u64, size: u64) -> Self {
        Self { gpa, size }
    }
}

pub struct WritePhysical {
    gpa: u64,
    data: Option<Vec<u8>>,
}
impl Message for WritePhysical {}
impl Messenger for WritePhysical {
    type Reply = ();
}
impl Msg for WritePhysical {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_VM_WRITE_PHYSICAL as u16;
        let data = self.data.take().unwrap();
        let data_len = data.len();

        let msg_sz = size_of::<kvmi_vm_write_physical>() + data_len;
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);

        let mut msg = VecBuf::<kvmi_vm_write_physical>::new();
        unsafe {
            let typed = msg.as_mut_type();
            typed.gpa = self.gpa;
            typed.size = data_len as u64;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (Some(req_n_rx), vec![hdr.into(), msg.into(), data])
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error writing to physical address: 0x{:x?}", self.gpa,),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
impl WritePhysical {
    pub fn new(gpa: u64, data: Vec<u8>) -> Self {
        Self {
            gpa,
            data: Some(data),
        }
    }
}

pub struct ControlSingleStep {
    vcpu: u16,
    enable: bool,
}
impl Message for ControlSingleStep {}
impl Messenger for ControlSingleStep {
    type Reply = ();
}
impl Msg for ControlSingleStep {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>) {
        let kind = KVMI_VCPU_CONTROL_SINGLESTEP as u16;
        let msg_sz = size_of::<kvmi_vcpu_hdr>() + size_of::<kvmi_vcpu_control_singlestep>();
        let seq = new_seq();
        let hdr = get_header(kind, msg_sz as u16, seq);

        let mut vcpu_msg = VecBuf::<kvmi_vcpu_hdr>::new();
        let mut ss_msg = VecBuf::<kvmi_vcpu_control_singlestep>::new();
        unsafe {
            let vcpu = vcpu_msg.as_mut_type();
            vcpu.vcpu = self.vcpu;

            let ss = ss_msg.as_mut_type();
            ss.enable = self.enable as u8;
        }

        let req_n_rx = get_request(kind, 0, seq);
        (
            Some(req_n_rx),
            vec![hdr.into(), vcpu_msg.into(), ss_msg.into()],
        )
    }
    fn get_error(&self, _e: Option<Error>) -> Error {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Error setting single step: {}", self.enable),
        )
        .into()
    }
    fn construct_reply(&self, _result: Vec<u8>) -> Self::Reply {}
}
impl ControlSingleStep {
    pub fn new(vcpu: u16, enable: bool) -> Self {
        Self { vcpu, enable }
    }
}
