use std::mem::size_of;

pub use binding::*;

#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(unused)]
#[allow(
    clippy::unreadable_literal,
    clippy::useless_transmute,
    clippy::trivially_copy_pass_by_ref,
    clippy::too_many_arguments,
    clippy::transmute_ptr_to_ptr
)]
mod binding {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[repr(C)]
pub struct HSFromWire {
    pub size: u32,
    pub uuid: [u8; 16],
    pub cpu_type: u8,
    pub padding: [u8; 3],
    pub start_time: i64,
    pub name: [u8; 64],
}

#[repr(C)]
pub struct HSToWire {
    size: u32,
    pub cookie_hash: [u8; 20],
}

impl Default for HSToWire {
    fn default() -> Self {
        HSToWire {
            size: size_of::<HSToWire>() as u32,
            cookie_hash: [0u8; 20],
        }
    }
}
impl HSToWire {
    pub fn new() -> Self {
        Self::default()
    }
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
    pub cmd: kvmi_vcpu_pause,
}

#[repr(C)]
pub struct ControlCmdRespMsg {
    pub hdr: kvmi_msg_hdr,
    pub cmd: kvmi_vm_control_cmd_response,
}

#[repr(C)]
pub struct VcpuControlEventsMsg {
    pub hdr: kvmi_vcpu_hdr,
    pub cmd: kvmi_vcpu_control_events,
}

#[repr(C)]
pub struct ControlCRMsg {
    pub hdr: kvmi_vcpu_hdr,
    pub cmd: kvmi_vcpu_control_cr,
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
#[derive(Debug)]
#[repr(transparent)]
pub struct KvmiEventSingleStep(kvmi_event_singlestep);

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

impl KvmiEventBreakpoint {
    pub fn get_gpa(&self) -> u64 {
        self.0.gpa
    }

    pub fn get_insn_len(&self) -> u8 {
        self.0.insn_len
    }
}

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct PageAccessEntry(kvmi_page_access_entry);

pub struct PageAccessEntryBuilder {
    gpa: u64,
    access: u8,
}

impl PageAccessEntryBuilder {
    pub fn new(gpa: u64) -> Self {
        Self { gpa, access: 0 }
    }

    pub fn gpa(&mut self, gpa: u64) -> &mut Self {
        self.gpa = gpa;
        self
    }

    pub fn set_write(&mut self) -> &mut Self {
        self.access |= KVMI_PAGE_ACCESS_W as u8;
        self
    }
    pub fn set_read(&mut self) -> &mut Self {
        self.access |= KVMI_PAGE_ACCESS_R as u8;
        self
    }
    pub fn set_execute(&mut self) -> &mut Self {
        self.access |= KVMI_PAGE_ACCESS_X as u8;
        self
    }
    pub fn clear_write(&mut self) -> &mut Self {
        self.access &= !(KVMI_PAGE_ACCESS_W as u8);
        self
    }
    pub fn clear_read(&mut self) -> &mut Self {
        self.access &= !(KVMI_PAGE_ACCESS_R as u8);
        self
    }
    pub fn clear_execute(&mut self) -> &mut Self {
        self.access &= !(KVMI_PAGE_ACCESS_X as u8);
        self
    }
    pub fn build(&self) -> PageAccessEntry {
        PageAccessEntry(kvmi_page_access_entry {
            gpa: self.gpa,
            access: self.access,
            padding1: 0,
            padding2: 0,
            padding3: 0,
        })
    }
}

impl PartialEq for kvmi_vcpu_get_registers_reply {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.padding == other.padding
            && self.regs == other.regs
            && self.sregs == other.sregs
    }
}
