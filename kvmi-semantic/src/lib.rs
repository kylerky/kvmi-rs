#[cfg(test)]
mod tests;

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
}

#[derive(Debug, PartialEq)]
enum PageMode {
    Real,
    IA32e,
    Other,
}

impl Domain {
    const IA32_LSTAR: u32 = 0xC000_0082;
    const IA32_CSTAR: u32 = 0xC000_0083;
    pub async fn new<T, F>(stream: T, validator: F, profile: &RekallProfile) -> Result<Self>
    where
        T: Write + Read + Send + AsRawFd + Unpin + 'static,
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let dom = DomainBuilder::new(stream);
        let (mut dom, event_rx) = dom.handshake(validator).await?;

        let msg = GetRegisters::new(0, vec![Self::IA32_LSTAR, Self::IA32_CSTAR]);
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

        info!("kernel base virtual address: 0x{:?}", kernel_base_va);

        Ok(Self { dom, event_rx })
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
            ("KiSystemCall64Shadow", Self::IA32_LSTAR),
            ("KiSystemCall32Shadow", Self::IA32_CSTAR),
        ]
        .iter()
        .map(|(symbol, msr)| {
            let symbol_rva = match functions.get(&symbol[..]) {
                Some(addr) => addr,
                None => return Err(Error::KernelVAddr),
            };

            if let Some(data) = msrs.get(msr) {
                debug!("{}: 0x{}", symbol, symbol_rva);
                debug!("msr(0x{}): 0x{}", msr, data);
                Ok(data - symbol_rva)
            } else {
                Err(Error::KernelVAddr)
            }
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
    Unsupported,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            KVMI(e) => write!(f, "{}", e),
            Unsupported => write!(f, "Guest not supported"),
            KernelVAddr => write!(f, "failed to get the virtual address of the kernel"),
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
            KVMI(kvmi_err) => kvmi_err.into(),
        }
    }
}
