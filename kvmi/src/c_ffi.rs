#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused)]

use std::mem::size_of;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[repr(C)]
pub struct HSFromWire {
    pub size: u32,
    pub uuid: [u8; 16],
    pub padding: u32,
    pub start_time: i64,
    pub name: [u8; 64],
}

#[repr(C)]
pub struct HSToWire {
    size: u32,
    pub cookie_hash: [u8; 20],
}

impl HSToWire {
    pub fn new() -> Self {
        HSToWire {
            size: size_of::<HSToWire>() as u32,
            cookie_hash: [0u8; 20],
        }
    }
}

#[repr(C)]
pub union EventReplyExtra {
    pub cr: kvmi_event_cr_reply,
    pub msr: kvmi_event_msr_reply,
    pub pf: kvmi_event_pf_reply,
}

#[repr(C)]
pub struct EventReply {
    pub hdr: kvmi_vcpu_hdr,
    pub common: kvmi_event_reply,
}

#[repr(C)]
pub struct PauseVCPUMsg {
    pub hdr: kvmi_msg_hdr,
    pub vcpu_hdr: kvmi_vcpu_hdr,
    pub cmd: kvmi_pause_vcpu,
}

#[repr(C)]
pub struct ControlCmdRespMsg {
    pub hdr: kvmi_msg_hdr,
    pub cmd: kvmi_control_cmd_response,
}

#[repr(C)]
pub struct ControlEventsMsg {
    pub hdr: kvmi_vcpu_hdr,
    pub cmd: kvmi_control_events,
}

#[repr(C)]
pub struct ControlCRMsg {
    pub hdr: kvmi_vcpu_hdr,
    pub cmd: kvmi_control_cr,
}

#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEvent(pub(super) kvmi_event);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventCR(kvmi_event_cr);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventMSR(kvmi_event_msr);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventBreakpoint(kvmi_event_breakpoint);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventPF(kvmi_event_pf);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventTrap(kvmi_event_trap);
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventDescriptor(kvmi_event_descriptor);

impl KvmiEventPF {
    pub fn as_raw_ref(&self) -> &kvmi_event_pf {
        &self.0
    }
}

impl KvmiEventCR {
    pub fn get_cr_num(&self) -> u16 {
        self.0.cr
    }
    pub fn get_old_val(&self) -> u64 {
        self.0.old_value
    }
    pub fn get_new_val(&self) -> u64 {
        self.0.new_value
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct PageAccessEntry(kvmi_page_access_entry);

impl PageAccessEntry {
    pub fn new(gpa: u64) -> Self {
        Self(kvmi_page_access_entry {
            gpa,
            access: 0,
            padding1: 0,
            padding2: 0,
            padding3: 0,
        })
    }

    pub fn set_write(mut self) -> Self {
        self.0.access |= KVMI_PAGE_ACCESS_W as u8;
        self
    }
    pub fn set_read(mut self) -> Self {
        self.0.access |= KVMI_PAGE_ACCESS_R as u8;
        self
    }
    pub fn set_execute(mut self) -> Self {
        self.0.access |= KVMI_PAGE_ACCESS_X as u8;
        self
    }
}
