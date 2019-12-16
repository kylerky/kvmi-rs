#[cfg(test)]
mod tests;

pub mod event;
pub use memory::address_space;

pub use kvmi::{Action, HSToWire};

use event::*;

pub mod tracing;

pub mod memory;
use memory::address_space::{IA32eAddrT, IA32eVirtual, KVMIPhysical, PhysicalAddrT};
use memory::process::{self, PSChanT};
use memory::CR3_MASK;

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;
use async_std::sync::{Arc, Receiver};

use kvmi::message::{
    CommonEventReply, ControlEvent, GetRegisters, GetRegistersReply, GetVCPUNum, PauseVCPUs,
    SetSingleStep,
};
use kvmi::DomainBuilder;

use log::{debug, info};

use std::collections::HashMap;
use std::convert::TryInto;
use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::mem;
use std::string::FromUtf16Error;

use serde::Deserialize;

use serde_json::Value;

#[macro_use]
extern crate lazy_static;

type Result<T> = std::result::Result<T, Error>;

pub struct Domain {
    k_vspace: IA32eVirtual,
    vspaces: HashMap<PhysicalAddrT, IA32eVirtual>,
    event_rx: Receiver<Event>,
    kernel_base_va: IA32eAddrT,
    profile: RekallProfile,
}

#[derive(Debug, PartialEq)]
enum PageMode {
    Real,
    IA32e,
    Other,
}

const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_CSTAR: u32 = 0xC000_0083;

const EPROCESS: &str = "_EPROCESS";
const KPROCESS: &str = "_KPROCESS";

const PTR_SZ: usize = mem::size_of::<u64>();
const PAGE_SHIFT: u32 = 12;

const KUSER_SHARED_DATA: &str = "_KUSER_SHARED_DATA";
const LIST_ENTRY: &str = "_LIST_ENTRY";
const FLINK: &str = "Flink";
const BLINK: &str = "Blink";

const LLP64_ULONG_SZ: usize = 4;

impl Domain {
    pub async fn new<T, F>(
        stream: T,
        validator: F,
        profile: RekallProfile,
        ptb: Option<u64>,
    ) -> Result<Self>
    where
        T: Write + Read + Send + AsRawFd + Unpin + 'static,
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let dom = DomainBuilder::new(stream);
        let (dom, event_rx) = dom.handshake(validator).await?;

        let msg = GetRegisters::new(0, vec![IA32_LSTAR, IA32_CSTAR]);
        let reply = dom.send(msg).await?;

        let paging = Self::get_paging_mode_from(&reply);

        info!("paging mode: {:?}", paging);

        match paging {
            PageMode::IA32e => (),
            _ => return Err(Error::Unsupported(String::from("unsupported paging mode"))),
        }

        let p_space = Arc::new(KVMIPhysical::from(dom));
        let (kernel_base_va, _kernel_base_pa, mut k_vspace) =
            memory::find_kernel_addr(p_space, &reply, &profile).await?;

        if let Some(ptb) = ptb {
            k_vspace.set_ptb(ptb);
        } else if memory::get_system_page_table(&mut k_vspace, kernel_base_va, &profile).await? {
            info!("Page table base of System: 0x{:x?}", k_vspace.get_ptb());
        } else {
            return Err(Error::PageTable);
        }

        let vspaces = [(k_vspace.get_ptb(), k_vspace.clone())]
            .iter()
            .cloned()
            .collect();
        Ok(Self {
            k_vspace,
            vspaces,
            event_rx,
            kernel_base_va,
            profile,
        })
    }

    fn get_paging_mode_from(reply: &GetRegistersReply) -> PageMode {
        use PageMode::*;

        let regs = reply.get_regs();
        let cr0 = regs.sregs.cr0;

        if cr0 & (1 << 31) == 0 {
            return Real;
        }

        let cr4 = regs.sregs.cr4;
        let pae = cr4 & (1 << 5);

        let efer = regs.sregs.efer;
        let lme = efer & (1 << 8);

        if pae != 0 && lme != 0 {
            return IA32e;
        }

        Other
    }

    pub async fn traverse_process_list(&self) -> Result<()> {
        let process_head =
            self.kernel_base_va + get_ksymbol_offset(&self.profile, "PsActiveProcessHead")?;
        process::process_list_traversal(
            self.k_vspace.clone(),
            |processes| Self::print_eprocess(&self.k_vspace, processes, &self.profile),
            process_head,
            &self.profile,
        )
        .await??;
        Ok(())
    }

    async fn print_eprocess(
        v_space: &IA32eVirtual,
        processes: Receiver<PSChanT>,
        profile: &RekallProfile,
    ) -> Result<()> {
        let pid_rva = get_struct_field_offset(profile, EPROCESS, "UniqueProcessId")?;
        // skip the list head
        processes.recv().await;
        while let Some(process) = processes.recv().await {
            let process = process?;
            if let Some(pid) = v_space.read(process + pid_rva, PTR_SZ).await? {
                let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
                debug!("process: 0x{:x?}, pid: 0x{:x?}", process, pid);
            }
        }
        Ok(())
    }

    pub fn get_event_stream(&self) -> &Receiver<Event> {
        &self.event_rx
    }

    pub async fn get_vcpu_num(&self) -> Result<u32> {
        let dom = self.k_vspace.get_base().get_dom();
        let num = dom.send(GetVCPUNum).await?;
        Ok(num)
    }

    pub async fn pause_vm(&self) -> Result<()> {
        let dom = self.k_vspace.get_base().get_dom();
        let num = dom.send(GetVCPUNum).await?;
        dom.send(PauseVCPUs::new(num).unwrap()).await?;
        Ok(())
    }

    pub async fn toggle_event(&self, vcpu: u16, kind: EventKind, enable: bool) -> Result<()> {
        let dom = self.k_vspace.get_base().get_dom();
        dom.send(ControlEvent::new(vcpu, kind, enable)).await?;
        Ok(())
    }

    pub async fn reply(&self, event: &Event, action: Action) -> Result<()> {
        let dom = self.k_vspace.get_base().get_dom();
        dom.send(CommonEventReply::new(event, action).unwrap())
            .await?;
        Ok(())
    }

    pub async fn resume_from_bp(
        &self,
        orig: u8,
        event: &Event,
        extra: &KvmiEventBreakpoint,
        enable_ss: bool,
    ) -> Result<()> {
        tracing::resume_from_bp(&self.k_vspace, orig, event, extra, enable_ss).await
    }

    pub async fn set_bp_by_physical(&self, gpa: PhysicalAddrT) -> Result<()> {
        tracing::set_bp_by_physical(self.k_vspace.get_base(), gpa).await
    }

    pub async fn toggle_single_step(&self, vcpu: u16, enable: bool) -> Result<()> {
        let dom = self.k_vspace.get_base().get_dom();
        dom.send(SetSingleStep::new(vcpu, enable)).await?;
        Ok(())
    }

    pub fn get_ksymbol_offset(&self, symbol: &str) -> Result<IA32eAddrT> {
        get_ksymbol_offset(&self.profile, symbol)
    }

    pub fn get_kfunc_offset(&self, func: &str) -> Result<IA32eAddrT> {
        get_kfunc_offset(&self.profile, func)
    }

    pub fn get_kernel_base_va(&self) -> IA32eAddrT {
        self.kernel_base_va
    }

    pub fn get_k_vspace(&self) -> &IA32eVirtual {
        &self.k_vspace
    }

    pub fn get_vspace(&mut self, ptb: PhysicalAddrT) -> &IA32eVirtual {
        let base = self.k_vspace.get_base();
        self.vspaces
            .entry(ptb)
            .or_insert_with(|| IA32eVirtual::new(Arc::clone(base), ptb))
    }

    pub fn get_profile(&self) -> &RekallProfile {
        &self.profile
    }

    pub async fn get_current_process(&self, sregs: &kvm_sregs) -> Result<IA32eAddrT> {
        let process = process::get_current_process(&self.k_vspace, sregs, &self.profile).await?;
        Ok(process)
    }
}

fn get_ksymbol_offset(profile: &RekallProfile, symbol: &str) -> Result<IA32eAddrT> {
    profile
        .constants
        .get(symbol)
        .copied()
        .ok_or_else(|| Error::Profile(format!("Missing {}", symbol)))
}

fn get_kfunc_offset(profile: &RekallProfile, func: &str) -> Result<IA32eAddrT> {
    profile
        .functions
        .get(func)
        .copied()
        .ok_or_else(|| Error::Profile(format!("Missing {}", func)))
}

fn get_struct_field_offset(
    profile: &RekallProfile,
    struct_name: &str,
    field_name: &str,
) -> Result<IA32eAddrT> {
    let struct_arr = profile
        .structs
        .get(struct_name)
        .ok_or_else(|| Error::Profile(format!("Missing {}", struct_name)))?;
    let fields = struct_arr
        .get(1)
        .ok_or_else(|| Error::Profile(format!("Missing {}[1]", struct_name)))?;
    let field = fields
        .get(field_name)
        .ok_or_else(|| Error::Profile(format!("Missing {}[1].{}", struct_name, field_name)))?;
    let offset = field
        .get(0)
        .ok_or_else(|| Error::Profile(format!("Missing {}[1].{}[0]", struct_name, field_name)))?;
    let offset = offset.as_u64().ok_or_else(|| {
        Error::Profile(format!(
            "{}[1].{}[0] is not a json number that can fit into u64",
            struct_name, field_name
        ))
    })?;
    Ok(offset)
}

pub fn get_ptb_from(sregs: &kvm_sregs) -> PhysicalAddrT {
    sregs.cr3 & CR3_MASK
}

#[derive(Deserialize)]
pub struct RekallProfile {
    #[serde(rename(deserialize = "$FUNCTIONS"))]
    pub functions: HashMap<String, u64>,

    #[serde(rename(deserialize = "$CONSTANTS"))]
    pub constants: HashMap<String, u64>,

    #[serde(rename(deserialize = "$STRUCTS"))]
    pub structs: HashMap<String, Value>,
}

impl error::Error for Error {}

#[derive(Debug)]
pub enum Error {
    KVMI(kvmi::Error),
    KernelVAddr,
    KernelPAddr,
    Profile(String),
    Unsupported(String),
    PageTable,
    WrongEvent,
    PageBoundary,
    InvalidVAddr,
    FromUtf16(FromUtf16Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            Unsupported(s) => write!(f, "Operation not supported: {}", s),
            KernelVAddr => write!(f, "failed to get the virtual address of the kernel"),
            KernelPAddr => write!(f, "failed to get the physical address of the kernel"),
            PageTable => write!(f, "failed to find the page table of the kernel"),
            WrongEvent => write!(f, "Calling function using mismatched event"),
            PageBoundary => write!(f, "Reading or writing across page boundary"),
            InvalidVAddr => write!(f, "Reading or writing invalid virtual address"),
            KVMI(e) => write!(f, "{}", e),
            Profile(e) => write!(f, "Error in JSON profile: {}", e),
            FromUtf16(e) => write!(f, "Error converting from UTF-16: {}", e),
        }
    }
}

impl From<kvmi::Error> for Error {
    fn from(e: kvmi::Error) -> Self {
        Error::KVMI(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        use Error::*;
        match e {
            Unsupported(_) => io::Error::new(io::ErrorKind::Other, e),
            KernelVAddr | KernelPAddr | PageTable | PageBoundary | InvalidVAddr | Profile(_)
            | FromUtf16(_) => io::Error::new(io::ErrorKind::InvalidData, e),
            WrongEvent => io::Error::new(io::ErrorKind::InvalidInput, e),
            KVMI(kvmi_err) => kvmi_err.into(),
        }
    }
}

impl From<FromUtf16Error> for Error {
    fn from(e: FromUtf16Error) -> Self {
        Error::FromUtf16(e)
    }
}
