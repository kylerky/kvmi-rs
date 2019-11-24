#[cfg(test)]
mod tests;

mod memory;

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;
use async_std::sync;

use kvmi::message::{GetRegisters, GetRegistersReply};
use kvmi::{DomainBuilder, Event, HSToWire};

use log::{debug, info};

use std::collections::HashMap;
use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;

use serde::Deserialize;

type Result<T> = std::result::Result<T, Error>;

pub struct Domain {
    dom: kvmi::Domain,
    event_rx: sync::Receiver<Event>,
    kernel_base_pa: u64,
}

#[derive(Debug, PartialEq)]
enum PageMode {
    Real,
    IA32e,
    Other,
}

const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_CSTAR: u32 = 0xC000_0083;
const CR3_MASK: u64 = (!0u64) << 12;
impl Domain {
    pub async fn new<T, F>(stream: T, validator: F, profile: &RekallProfile) -> Result<Self>
    where
        T: Write + Read + Send + AsRawFd + Unpin + 'static,
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let dom = DomainBuilder::new(stream);
        let (mut dom, event_rx) = dom.handshake(validator).await?;

        let msg = GetRegisters::new(0, vec![IA32_LSTAR, IA32_CSTAR]);
        let reply = dom.send(msg).await?;

        let paging = Self::get_paging_mode_from(&reply);

        info!("paging mode: {:?}", paging);

        match paging {
            PageMode::IA32e => (),
            _ => return Err(Error::Unsupported),
        }

        let msrs: HashMap<u32, u64> = reply
            .get_msrs()
            .iter()
            .map(|msr| (msr.index, msr.data))
            .collect();

        let kernel_base_va = Self::get_kernel_va_from(&msrs, profile)?;

        let regs = reply.get_regs();
        let cr3 = regs.sregs.cr3;
        info!(
            "kernel base virtual address: 0x{:x?}, cr3: 0x{:x?}",
            kernel_base_va, cr3
        );

        let kernel_base_pa =
            memory::translate_v2p(&mut dom, cr3 & CR3_MASK, kernel_base_va).await?;

        let kernel_base_pa = kernel_base_pa.ok_or(Error::KernelPAddr)?;
        info!("kernel base physical address: 0x{:x?}", kernel_base_pa);

        Ok(Self {
            dom,
            event_rx,
            kernel_base_pa,
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

    fn get_kernel_va_from(msrs: &HashMap<u32, u64>, profile: &RekallProfile) -> Result<u64> {
        debug!("Finding kernel virtual address using KiSystemCall64Shadow & KiSystemCall32Shadow");

        let functions = &profile.functions;

        let va = [
            ("KiSystemCall64Shadow", IA32_LSTAR),
            ("KiSystemCall32Shadow", IA32_CSTAR),
        ]
        .iter()
        .map(|(symbol, msr)| {
            let symbol_rva = functions.get(&symbol[..]).ok_or(Error::KernelVAddr)?;

            let data = msrs
                .get(msr)
                .ok_or_else(|| Error::Profile(format!("Missing function: {}", symbol)))?;
            debug!("{}: 0x{:x?}", symbol, symbol_rva);
            debug!("msr(0x{:x?}): 0x{:x?}", msr, data);
            Ok(data - symbol_rva)
        })
        .collect::<Result<Vec<u64>>>()?;

        if va[0] != va[1] {
            return Err(Error::KernelVAddr);
        }

        Ok(va[0])
    }
}

#[derive(Deserialize)]
pub struct RekallProfile {
    #[serde(rename(deserialize = "$FUNCTIONS"))]
    functions: HashMap<String, u64>,
}

impl error::Error for Error {}

#[derive(Debug)]
pub enum Error {
    KVMI(kvmi::Error),
    KernelVAddr,
    KernelPAddr,
    Profile(String),
    Unsupported,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            KVMI(e) => write!(f, "{}", e),
            Unsupported => write!(f, "Guest not supported"),
            KernelVAddr => write!(f, "failed to get the virtual address of the kernel"),
            KernelPAddr => write!(f, "failed to get the physical address of the kernel"),
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
            KVMI(kvmi_err) => kvmi_err.into(),
            Profile(_) => io::Error::new(io::ErrorKind::InvalidInput, e),
        }
    }
}
