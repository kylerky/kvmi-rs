#[cfg(test)]
mod tests;

mod memory;

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;
use async_std::sync::{self, Arc, Receiver, Sender};
use async_std::task;

use kvmi::message::{GetMaxGfn, GetRegisters, GetRegistersReply, ReadPhysical};
use kvmi::{DomainBuilder, Event, HSToWire};

use log::{debug, info};

use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::mem;
use std::ops::Range;

use serde::Deserialize;

use serde_json::Value;

use regex::bytes::Regex;

#[macro_use]
extern crate lazy_static;

type Result<T> = std::result::Result<T, Error>;
type PSChanT = Result<u64>;

pub struct Domain {
    dom: Arc<kvmi::Domain>,
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

const EPROCESS: &str = "_EPROCESS";
const KPROCESS: &str = "_KPROCESS";

const PTR_SZ: u64 = mem::size_of::<u64>() as u64;
const PAGE_SHIFT: u32 = 12;

const SYSTEM_PID: u64 = 4;

const KI_USER_SHARED_DATA_PTR: u64 = 0xffff_f780_0000_0000;
const KUSER_SHARED_DATA: &str = "_KUSER_SHARED_DATA";

const LLP64_ULONG_SZ: u64 = 4;

impl Domain {
    pub async fn new<T, F>(stream: T, validator: F, profile: &RekallProfile) -> Result<Self>
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
            Self::find_kernel_addr(&dom, &reply, profile).await?;

        let dom = Arc::new(dom);
        let pt_base =
            Self::get_system_page_table(Arc::clone(&dom), kernel_base_va, pt_base, profile).await?;
        info!("Page table base of System: 0x{:x?}", pt_base);

        Ok(Self {
            dom,
            event_rx,
            kernel_base_pa,
        })
    }

    async fn find_kernel_addr(
        dom: &kvmi::Domain,
        reply: &GetRegistersReply,
        profile: &RekallProfile,
    ) -> Result<(u64, u64, u64)> {
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

        let pt_base = cr3 & CR3_MASK;
        let kernel_base_pa = memory::translate_v2p(dom, pt_base, kernel_base_va).await?;

        info!("kernel base physical address: 0x{:x?}", kernel_base_pa);
        let kernel_base_pa = kernel_base_pa.ok_or(Error::KernelPAddr)?;
        Ok((kernel_base_va, kernel_base_pa, pt_base))
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

    async fn get_system_page_table(
        dom: Arc<kvmi::Domain>,
        kernel_base_va: u64,
        pt_base: u64,
        profile: &RekallProfile,
    ) -> Result<Option<u64>> {
        let dtb_rva = get_struct_field_offset(profile, KPROCESS, "DirectoryTableBase")?;
        let flink_rva = get_struct_field_offset(profile, "_LIST_ENTRY", "Flink")?;
        let blink_rva = get_struct_field_offset(profile, "_LIST_ENTRY", "Blink")?;
        let name_rva = get_struct_field_offset(profile, EPROCESS, "ImageFileName")?;

        let pt_ptr = Self::by_ps_init_sys(&dom, kernel_base_va, pt_base, profile, dtb_rva).await?;
        if pt_ptr.is_some() {
            return Ok(pt_ptr);
        }

        let process_head = kernel_base_va + get_ksymbol_offset(profile, "PsActiveProcessHead")?;
        debug!("process_head: 0x{:x?}", process_head);
        Self::by_eprocess_list_traversal(
            Arc::clone(&dom),
            process_head,
            pt_base,
            profile,
            dtb_rva,
            flink_rva,
            blink_rva,
        )
        .await?;

        let max_gfn = dom.send(GetMaxGfn).await?;
        debug!("max_gfn: 0x{:?}", max_gfn);
        Self::by_physical_mem_scan(
            &dom,
            profile,
            0x1_0000..max_gfn << PAGE_SHIFT,
            name_rva,
            dtb_rva,
            flink_rva,
            blink_rva,
        )
        .await?;

        Ok(None)
    }

    async fn by_ps_init_sys(
        dom: &kvmi::Domain,
        kernel_base_va: u64,
        pt_base: u64,
        profile: &RekallProfile,
        dtb_rva: u64,
    ) -> Result<Option<u64>> {
        if let Some(proc_va) = Self::read_kptr(
            dom,
            "PsInitialSystemProcess",
            kernel_base_va,
            pt_base,
            profile,
        )
        .await?
        {
            debug!("System virtual address: 0x{:x?}", proc_va);
            if let Some(page_table_ptr) =
                Self::read_struct_field(dom, proc_va, dtb_rva, PTR_SZ, pt_base).await?
            {
                let page_table_ptr = u64::from_ne_bytes(page_table_ptr[..].try_into().unwrap());
                return Ok(Some(page_table_ptr));
            }
        }
        Ok(None)
    }

    async fn by_eprocess_list_traversal(
        dom: Arc<kvmi::Domain>,
        head: u64,
        pt_base: u64,
        profile: &RekallProfile,
        dtb_rva: u64,
        flink_rva: u64,
        blink_rva: u64,
    ) -> Result<Option<u64>> {
        let processes = Self::get_process_list_from(
            Arc::clone(&dom),
            head,
            pt_base,
            profile,
            flink_rva,
            blink_rva,
        )?;
        let pid_rva = get_struct_field_offset(profile, EPROCESS, "UniqueProcessId")?;
        // skip the list head
        processes.recv().await;
        while let Some(process) = processes.recv().await {
            let process = process?;
            if let Some(pid) =
                Self::read_struct_field(&dom, process, pid_rva, PTR_SZ, pt_base).await?
            {
                let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
                if pid == SYSTEM_PID {
                    let dtb =
                        Self::read_struct_field(&dom, process, dtb_rva, PTR_SZ, pt_base).await?;
                    if let Some(dtb) = dtb {
                        let dtb = u64::from_ne_bytes(dtb[..].try_into().unwrap());
                        // sanity check of dtb
                        if dtb > 0 && dtb.trailing_zeros() >= PAGE_SHIFT {
                            return Ok(Some(dtb));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    #[allow(clippy::trivial_regex)]
    async fn by_physical_mem_scan(
        dom: &kvmi::Domain,
        profile: &RekallProfile,
        addr_range: Range<u64>,
        name_rva: u64,
        dtb_rva: u64,
        flink_rva: u64,
        blink_rva: u64,
    ) -> Result<Option<u64>> {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"(?-u)System\x00").unwrap();
        }
        let major_rva = get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMajorVersion")?;
        let minor_rva = get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMinorVersion")?;

        let name_rva = name_rva as isize;
        let page_sz: u64 = 1 << PAGE_SHIFT;
        let mut prev_page = vec![0u8; page_sz as usize];
        for addr in addr_range.clone().step_by(page_sz as usize) {
            let page = dom.send(ReadPhysical::new(addr, page_sz)).await?;
            let matches = RE
                .find_iter(&page[..])
                .map(|mat| {
                    let proc_offset = mat.start() as isize - name_rva;

                    let read_page_from = |rva, sz| {
                        let offset = proc_offset + rva as isize;
                        if offset >= 0 {
                            let start = offset as usize;
                            let end = start + sz as usize;
                            if end > page_sz as usize {
                                None
                            } else {
                                Some(&page[start..end])
                            }
                        } else {
                            let start = (prev_page.len() as isize + offset) as usize;
                            let end = start + sz as usize;
                            if end > page_sz as usize {
                                None
                            } else {
                                Some(&prev_page[start..end])
                            }
                        }
                    };

                    let dtb = read_page_from(dtb_rva, PTR_SZ);
                    let flink = read_page_from(flink_rva, PTR_SZ);

                    (proc_offset, dtb, flink)
                })
                .filter(|(_, dtb, flink)| dtb.is_some() && flink.is_some())
                .map(|(proc_offset, dtb, flink)| {
                    let dtb = u64::from_ne_bytes(dtb.unwrap().try_into().unwrap());
                    let flink = u64::from_ne_bytes(flink.unwrap().try_into().unwrap());
                    (proc_offset, dtb, flink)
                })
                .filter(|(_, dtb, flink)| {
                    *flink > 0
                        && *dtb > 0
                        && *dtb < addr_range.end
                        && dtb.trailing_zeros() >= PAGE_SHIFT
                });

            for (_offset, dtb, flink) in matches {
                debug!("verifying dtb: 0x{:x?}", dtb);
                if !Self::verify_by_user_shared(dom, major_rva, minor_rva, addr_range.end, dtb)
                    .await?
                {
                    debug!("dtb: 0x{:x?} filtered by user shared data", dtb);
                    continue;
                }
                if !Self::verify_by_thread_list(dom, dtb, flink, flink_rva, blink_rva).await? {
                    debug!("dtb: 0x{:x?} filtered by thread list reflection test", dtb);
                    continue;
                }
                return Ok(Some(dtb));
            }

            prev_page = page;
        }
        Ok(None)
    }

    async fn verify_by_user_shared(
        dom: &kvmi::Domain,
        major_rva: u64,
        minor_rva: u64,
        max_paddr: u64,
        dtb: u64,
    ) -> Result<bool> {
        debug!("verifying by user shared");
        let major_pa = memory::translate_v2p(dom, dtb, KI_USER_SHARED_DATA_PTR + major_rva).await?;
        let minor_pa = memory::translate_v2p(dom, dtb, KI_USER_SHARED_DATA_PTR + minor_rva).await?;
        match (major_pa, minor_pa) {
            (Some(major_pa), Some(minor_pa)) => {
                if major_pa >= max_paddr || minor_pa >= max_paddr {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }

        let major =
            Self::read_struct_field(dom, KI_USER_SHARED_DATA_PTR, major_rva, LLP64_ULONG_SZ, dtb)
                .await?;
        let minor =
            Self::read_struct_field(dom, KI_USER_SHARED_DATA_PTR, minor_rva, LLP64_ULONG_SZ, dtb)
                .await?;
        match (major, minor) {
            (Some(major), Some(minor)) => {
                let major = u32::from_ne_bytes(major[..].try_into().unwrap());
                let minor = u32::from_ne_bytes(minor[..].try_into().unwrap());
                match (major, minor) {
                    (10, 0) => Ok(true),
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn verify_by_thread_list(
        dom: &kvmi::Domain,
        dtb: u64,
        flink: u64,
        flink_rva: u64,
        blink_rva: u64,
    ) -> Result<bool> {
        debug!("verifying by thread list");
        let blink = Self::read_struct_field(&dom, flink, blink_rva, PTR_SZ, dtb).await?;
        if let Some(blink) = blink {
            let blink = u64::from_ne_bytes(blink[..].try_into().unwrap());

            let flink_test = Self::read_struct_field(&dom, blink, flink_rva, PTR_SZ, dtb).await?;
            if let Some(flink_test) = flink_test {
                let flink_test = u64::from_ne_bytes(flink_test[..].try_into().unwrap());
                let passed = flink == flink_test;
                return Ok(passed);
            }
        }
        Ok(false)
    }

    async fn read_struct_field(
        dom: &kvmi::Domain,
        struct_va: u64,
        field_offset: u64,
        field_sz: u64,
        pt_base: u64,
    ) -> Result<Option<Vec<u8>>> {
        let pa = memory::translate_v2p(dom, pt_base, struct_va + field_offset).await?;

        if let Some(pa) = pa {
            let val = dom.send(ReadPhysical::new(pa, field_sz)).await?;

            return Ok(Some(val));
        }
        Ok(None)
    }

    fn get_process_list_from(
        dom: Arc<kvmi::Domain>,
        head: u64,
        pt_base: u64,
        profile: &RekallProfile,
        flink_rva: u64,
        blink_rva: u64,
    ) -> Result<Receiver<PSChanT>> {
        let links_rva = get_struct_field_offset(profile, EPROCESS, "ActiveProcessLinks")?;

        let (tx, rx) = sync::channel(1);
        task::spawn(async move {
            Self::traverse_process_list(dom, head, pt_base, flink_rva, blink_rva, links_rva, tx)
                .await;
        });

        Ok(rx)
    }

    async fn traverse_process_list(
        dom: Arc<kvmi::Domain>,
        head: u64,
        pt_base: u64,
        flink_rva: u64,
        blink_rva: u64,
        links_rva: u64,
        tx: Sender<PSChanT>,
    ) {
        if head < links_rva {
            return;
        }

        let mut seen = HashSet::new();
        let mut processes = vec![];
        processes.push(head);
        seen.insert(head);
        while let Some(link) = processes.pop() {
            tx.send(Ok(link - links_rva)).await;
            let links = match Self::read_struct_field(&dom, link, 0, PTR_SZ * 2, pt_base).await {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(e) => {
                    tx.send(Err(e)).await;
                    break;
                }
            };
            let links: Vec<u64> = [blink_rva, flink_rva]
                .iter()
                .map(|rva| {
                    let start = *rva as usize;
                    let end = start + PTR_SZ as usize;
                    u64::from_ne_bytes(links[start..end].try_into().unwrap())
                })
                .filter(|l| !seen.contains(l) && *l >= links_rva)
                .collect();
            debug!("links: {:x?}", links);
            for l in links {
                processes.push(l);
                seen.insert(l);
            }
        }
    }

    async fn read_kptr(
        dom: &kvmi::Domain,
        symbol: &str,
        kernel_base_va: u64,
        pt_base: u64,
        profile: &RekallProfile,
    ) -> Result<Option<u64>> {
        let ptr_rva = get_ksymbol_offset(profile, symbol)?;
        let ptr_pa = memory::translate_v2p(dom, pt_base, kernel_base_va + ptr_rva).await?;
        if let Some(ptr_pa) = ptr_pa {
            let val = dom.send(ReadPhysical::new(ptr_pa, PTR_SZ)).await?;
            let val = u64::from_ne_bytes(val[..].try_into().unwrap());
            Ok(Some(val))
        } else {
            Ok(None)
        }
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
            Profile(_) => io::Error::new(io::ErrorKind::InvalidData, e),
        }
    }
}
