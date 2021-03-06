pub mod address_space;
pub mod handle_table;
pub(super) mod process;

pub mod list;
pub mod modules;

use crate::{Error, RekallProfile, Result};
use crate::{
    EPROCESS, IA32_CSTAR, IA32_LSTAR, KPROCESS, KUSER_SHARED_DATA, LLP64_ULONG_SZ, PAGE_SHIFT,
    PTR_SZ,
};

use address_space::{IA32eAddrT, IA32eVirtual, KVMIPhysical};

use kvmi::message::{GetMaxGfn, GetRegistersReply};

use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Range;
use std::os::unix::io::AsRawFd;

use async_std::sync::Arc;

use log::{debug, info};

use regex::bytes::Regex;

// [12..52] bit of the entry
const KI_USER_SHARED_DATA_PTR: u64 = 0xffff_f780_0000_0000;
pub(super) const CR3_MASK: u64 = (!0u64) << 12;

const UNICODE_STRING_SZ: usize = 16;

async fn read_kptr<T: AsRawFd>(
    addr_space: &IA32eVirtual<T>,
    symbol: &str,
    kernel_base_va: u64,
    profile: &RekallProfile,
) -> Result<u64> {
    let ptr_rva = crate::get_symbol_offset(profile, symbol)?;

    let data = addr_space.read(kernel_base_va + ptr_rva, PTR_SZ).await?;
    Ok(u64::from_ne_bytes(data[..].try_into().unwrap()))
}

pub(super) async fn get_system_page_table<T>(
    v_space: &mut IA32eVirtual<T>,
    kernel_base_va: u64,
    profile: &RekallProfile,
) -> Result<bool>
where
    T: AsRawFd + Send + Sync,
{
    let dtb_rva = crate::get_struct_field_offset(profile, KPROCESS, "DirectoryTableBase")?;
    let flink_rva = crate::get_struct_field_offset(profile, "_LIST_ENTRY", "Flink")?;
    let blink_rva = crate::get_struct_field_offset(profile, "_LIST_ENTRY", "Blink")?;
    let name_rva = crate::get_struct_field_offset(profile, EPROCESS, "ImageFileName")?;

    debug!("trying to get page table base from PsInitialSystemProcess");
    let ptb = process::by_ps_init_sys(v_space, kernel_base_va, profile, dtb_rva).await;
    match ptb {
        Ok(ptb) => {
            v_space.set_ptb(ptb);
            return Ok(true);
        }
        Err(Error::InvalidVAddr) => (),
        Err(e) => return Err(e),
    }

    debug!("trying to get page table base from process list");
    let process_head = kernel_base_va + crate::get_symbol_offset(profile, "PsActiveProcessHead")?;
    debug!("process_head: 0x{:x?}", process_head);
    let ptb = {
        process::process_list_traversal(
            v_space.clone(),
            |processes| process::by_eprocess_list_traversal(v_space, processes, profile, dtb_rva),
            process_head,
            profile,
        )
        .await?
    };
    match ptb {
        Ok(ptb) => {
            v_space.set_ptb(ptb);
            return Ok(true);
        }
        Err(Error::InvalidVAddr) => (),
        Err(e) => return Err(e),
    }

    debug!("trying to get page table base by scanning");
    let max_gfn = {
        let physical = v_space.get_base();
        let dom = physical.get_dom();
        dom.send(GetMaxGfn).await?
    };
    debug!("max_gfn: 0x{:?}", max_gfn);
    let ptb = by_physical_mem_scan(
        v_space,
        profile,
        0x10_0000..max_gfn << PAGE_SHIFT,
        name_rva,
        dtb_rva,
        flink_rva,
        blink_rva,
    )
    .await;
    match ptb {
        Ok(ptb) => {
            v_space.set_ptb(ptb);
            Ok(true)
        }
        Err(Error::InvalidVAddr) => Ok(false),
        Err(e) => Err(e),
    }
}

#[allow(clippy::trivial_regex)]
pub(super) async fn by_physical_mem_scan<T: AsRawFd>(
    v_space: &IA32eVirtual<T>,
    profile: &RekallProfile,
    addr_range: Range<u64>,
    name_rva: u64,
    dtb_rva: u64,
    flink_rva: u64,
    blink_rva: u64,
) -> Result<u64> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"(?-u)System\x00").unwrap();
    }
    let major_rva = crate::get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMajorVersion")?;
    let minor_rva = crate::get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMinorVersion")?;

    let name_rva = name_rva as isize;
    let page_sz = 1 << PAGE_SHIFT;
    let mut prev_page = vec![0u8; page_sz];
    for addr in addr_range.clone().step_by(page_sz) {
        let page = {
            let p_space = v_space.get_base();
            p_space.read(addr, page_sz).await?
        };
        let matches: Vec<(isize, u64, u64)> = RE
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
                (proc_offset, dtb & CR3_MASK, flink)
            })
            .filter(|(_, dtb, flink)| *flink > 0 && *dtb > 0 && *dtb < addr_range.end)
            .collect();

        for (_offset, dtb, flink) in matches {
            debug!("verifying dtb: 0x{:x?}", dtb);
            let v_space2 = IA32eVirtual::new(Arc::clone(v_space.get_base()), dtb);
            if !verify_by_user_shared(&v_space2, major_rva, minor_rva).await? {
                debug!("dtb: 0x{:x?} filtered by user shared data", dtb);
                continue;
            }
            if !verify_by_thread_list(&v_space2, flink, flink_rva, blink_rva).await? {
                debug!("dtb: 0x{:x?} filtered by thread list reflection test", dtb);
                continue;
            }
            return Ok(dtb);
        }

        prev_page = page;
    }
    Err(Error::InvalidVAddr)
}

async fn verify_by_user_shared<T: AsRawFd>(
    addr_space: &IA32eVirtual<T>,
    major_rva: u64,
    minor_rva: u64,
) -> Result<bool> {
    debug!("verifying by user shared");
    match get_major_minor(addr_space, major_rva, minor_rva).await {
        Ok((10, 0)) => Ok(true),
        Ok(_) | Err(Error::InvalidVAddr) => Ok(false),
        Err(e) => Err(e),
    }
}

async fn get_major_minor<T: AsRawFd>(
    addr_space: &IA32eVirtual<T>,
    major_rva: u64,
    minor_rva: u64,
) -> Result<(u32, u32)> {
    let major = addr_space
        .read(KI_USER_SHARED_DATA_PTR + major_rva, LLP64_ULONG_SZ)
        .await?;
    let minor = addr_space
        .read(KI_USER_SHARED_DATA_PTR + minor_rva, LLP64_ULONG_SZ)
        .await?;
    let major = u32::from_ne_bytes(major[..].try_into().unwrap());
    let minor = u32::from_ne_bytes(minor[..].try_into().unwrap());
    Ok((major, minor))
}

async fn verify_by_thread_list<T: AsRawFd>(
    addr_space: &IA32eVirtual<T>,
    flink: u64,
    flink_rva: u64,
    blink_rva: u64,
) -> Result<bool> {
    debug!("verifying by thread list");
    let blink = match addr_space.read(flink + blink_rva, PTR_SZ).await {
        Ok(r) => r,
        Err(Error::InvalidVAddr) => return Ok(false),
        Err(e) => return Err(e),
    };
    let blink = u64::from_ne_bytes(blink[..].try_into().unwrap());

    let flink_test = match addr_space.read(blink + flink_rva, PTR_SZ).await {
        Ok(r) => r,
        Err(Error::InvalidVAddr) => return Ok(false),
        Err(e) => return Err(e),
    };
    let flink_test = u64::from_ne_bytes(flink_test[..].try_into().unwrap());

    let passed = flink == flink_test;
    Ok(passed)
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

pub(super) async fn find_kernel_addr<T: AsRawFd>(
    p_space: Arc<KVMIPhysical<T>>,
    reply: &GetRegistersReply,
    profile: &RekallProfile,
) -> Result<(u64, u64, IA32eVirtual<T>)> {
    let msrs: HashMap<u32, u64> = reply
        .get_msrs()
        .iter()
        .map(|msr| (msr.index, msr.data))
        .collect();

    let kernel_base_va = get_kernel_va_from(&msrs, profile)?;
    let regs = reply.get_regs();
    let cr3 = regs.sregs.cr3;
    info!(
        "kernel base virtual address: 0x{:x?}, cr3: 0x{:x?}",
        kernel_base_va, cr3
    );

    let pt_base = cr3 & CR3_MASK;
    let v_space = IA32eVirtual::new(p_space, pt_base);

    let kernel_base_pa = v_space.lookup(kernel_base_va).await;

    let kernel_base_pa = kernel_base_pa.map_err(|e| match e {
        Error::InvalidVAddr => Error::KernelPAddr,
        err => err,
    })?;
    info!("kernel base physical address: 0x{:x?}", kernel_base_pa);

    Ok((kernel_base_va, kernel_base_pa, v_space))
}

pub async fn read_utf8<T: AsRawFd>(v_space: &IA32eVirtual<T>, addr: IA32eAddrT) -> Result<String> {
    let str_struct = v_space.read(addr, UNICODE_STRING_SZ).await?;

    let length = u16::from_ne_bytes(str_struct[..2].try_into().unwrap());
    let buffer_ptr = IA32eAddrT::from_ne_bytes(str_struct[8..].try_into().unwrap());

    let buffer = v_space.read(buffer_ptr, length as usize).await?;
    let res = String::from_utf8(buffer)?;

    Ok(res)
}

pub async fn read_utf16<T: AsRawFd>(v_space: &IA32eVirtual<T>, addr: IA32eAddrT) -> Result<String> {
    let str_struct = v_space.read(addr, UNICODE_STRING_SZ).await?;

    let length = u16::from_ne_bytes(str_struct[..2].try_into().unwrap());
    let buffer_ptr = IA32eAddrT::from_ne_bytes(str_struct[8..].try_into().unwrap());

    let buffer = v_space.read(buffer_ptr, length as usize).await?;

    let buffer: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|bytes| u16::from_ne_bytes(bytes.try_into().unwrap()))
        .collect();
    let res = String::from_utf16(&buffer[..])?;

    Ok(res)
}
