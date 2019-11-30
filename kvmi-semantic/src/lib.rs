#[cfg(test)]
mod tests;

mod memory;

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;
use async_std::sync::{self, Arc};

use kvmi::message::{GetRegisters, GetRegistersReply};
use kvmi::{DomainBuilder, Event, HSToWire};

use log::info;

use std::collections::HashMap;
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
    dom: Arc<kvmi::Domain>,
    event_rx: sync::Receiver<Event>,
    kernel_base_va: u64,
    ptb: u64,
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

const PTR_SZ: u64 = mem::size_of::<u64>() as u64;
const PAGE_SHIFT: u32 = 12;

const KUSER_SHARED_DATA: &str = "_KUSER_SHARED_DATA";
const LIST_ENTRY: &str = "_LIST_ENTRY";
const FLINK: &str = "Flink";
const BLINK: &str = "Blink";

const LLP64_ULONG_SZ: u64 = 4;

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

        let (kernel_base_va, kernel_base_pa, pt_base) =
            memory::find_kernel_addr(&dom, &reply, &profile).await?;

        let dom = Arc::new(dom);
        if let Some(ptb) = ptb {
            Ok(Self {
                dom,
                event_rx,
                kernel_base_va,
                ptb,
                profile,
            })
        } else {
            let ptb =
                memory::get_system_page_table(Arc::clone(&dom), kernel_base_va, pt_base, &profile)
                    .await?;
            if let Some(ptb) = ptb {
                info!("Page table base of System: 0x{:x?}", pt_base);
                Ok(Self {
                    dom,
                    event_rx,
                    kernel_base_va,
                    ptb,
                    profile,
                })
            } else {
                Err(Error::PageTable)
            }
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
