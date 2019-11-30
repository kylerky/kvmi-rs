#[cfg(test)]
mod tests;

mod memory;
use memory::address_space::{IA32eVirtual, KVMIPhysical};
use memory::process::{self, PSChanT};

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;
use async_std::sync::{self, Receiver};

use kvmi::message::{GetRegisters, GetRegistersReply};
use kvmi::{DomainBuilder, Event, HSToWire};

use log::{debug, info};

use std::collections::HashMap;
use std::convert::TryInto;
use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::mem;

use serde::Deserialize;

use serde_json::Value;

#[macro_use]
extern crate lazy_static;

type Result<T> = std::result::Result<T, Error>;

pub struct Domain {
    v_space: IA32eVirtual,
    event_rx: sync::Receiver<Event>,
    kernel_base_va: u64,
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
            _ => return Err(Error::Unsupported),
        }

        let p_space = KVMIPhysical::from(dom);
        let (kernel_base_va, _kernel_base_pa, mut v_space) =
            memory::find_kernel_addr(p_space, &reply, &profile).await?;

        if let Some(ptb) = ptb {
            v_space.set_ptb(ptb);
            Ok(Self {
                v_space,
                event_rx,
                kernel_base_va,
                profile,
            })
        } else if memory::get_system_page_table(&mut v_space, kernel_base_va, &profile).await? {
            info!("Page table base of System: 0x{:x?}", v_space.get_ptb());
            Ok(Self {
                v_space,
                event_rx,
                kernel_base_va,
                profile,
            })
        } else {
            Err(Error::PageTable)
        }
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
            self.v_space.clone(),
            |processes| Self::print_eprocess(&self.v_space, processes, &self.profile),
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
}

fn get_ksymbol_offset(profile: &RekallProfile, symbol: &str) -> Result<u64> {
    profile
        .constants
        .get(symbol)
        .copied()
        .ok_or_else(|| Error::Profile(format!("Missing {}", symbol)))
}

fn get_struct_field_offset(
    profile: &RekallProfile,
    struct_name: &str,
    field_name: &str,
) -> Result<u64> {
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
    Unsupported,
    PageTable,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            Unsupported => write!(f, "Guest not supported"),
            KernelVAddr => write!(f, "failed to get the virtual address of the kernel"),
            KernelPAddr => write!(f, "failed to get the physical address of the kernel"),
            PageTable => write!(f, "failed to find the page tableof the kernel"),
            KVMI(e) => write!(f, "{}", e),
            Profile(e) => write!(f, "Error in JSON profile: {}", e),
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
            Unsupported => io::Error::new(io::ErrorKind::Other, e),
            KernelVAddr => io::Error::new(io::ErrorKind::InvalidData, e),
            KernelPAddr => io::Error::new(io::ErrorKind::InvalidData, e),
            PageTable => io::Error::new(io::ErrorKind::InvalidData, e),
            KVMI(kvmi_err) => kvmi_err.into(),
            Profile(_) => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}
