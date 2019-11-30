use crate::{Error, RekallProfile, Result};
use crate::{
    EPROCESS, IA32_CSTAR, IA32_LSTAR, KPROCESS, KUSER_SHARED_DATA, LLP64_ULONG_SZ, PAGE_SHIFT,
    PTR_SZ,
};

use kvmi::message::{GetMaxGfn, GetRegistersReply, ReadPhysical};

use std::collections::HashMap;
use std::convert::TryInto;
use std::ops::Range;

use async_std::sync::Arc;

use log::{debug, info};

use regex::bytes::Regex;

pub mod process;

// [12..52] bit of the entry
const ENTRY_POINTER_MASK: u64 = (!0u64) << 24 >> 12;
const PG_MASK: u64 = 1u64 << 7;
const P_MASK: u64 = 1;
const VA_MASK: u64 = 0xff8;
const KI_USER_SHARED_DATA_PTR: u64 = 0xffff_f780_0000_0000;
const CR3_MASK: u64 = (!0u64) << 12;

pub async fn translate_v2p(
    dom: &kvmi::Domain,
    table_base: u64,
    v_addr: u64,
) -> Result<Option<u64>> {
    let mut base = table_base;
    let mut level: u32 = 4;
    let result = loop {
        let offset = level * 9;
        // table lookup
        let v_addr_shift = (v_addr >> offset) & VA_MASK;
        let entry_addr = base | v_addr_shift;
        let entry = dom.send(ReadPhysical::new(entry_addr, 8)).await?;
        let entry = u64::from_ne_bytes(entry[..].try_into().unwrap());

        // check entry
        let (paddr, pg, present) = read_entry(entry);
        if !present {
            break None;
        }

        level -= 1;
        // add offset in a page frame
        if pg || level == 0 {
            let mask = (!0) << (offset + 3);
            break Some((paddr & mask) | (v_addr & !mask));
        }
        base = paddr;
    };
    Ok(result)
}

// Returns (gpa, PG, present)
fn read_entry(entry: u64) -> (u64, bool, bool) {
    let present = (entry & P_MASK) != 0;
    if present {
        let pg = (entry & PG_MASK) != 0;
        (entry & ENTRY_POINTER_MASK, pg, present)
    } else {
        (0, false, present)
    }
}

pub async fn read_struct_field(
    dom: &kvmi::Domain,
    struct_va: u64,
    field_offset: u64,
    field_sz: u64,
    pt_base: u64,
) -> Result<Option<Vec<u8>>> {
    let pa = translate_v2p(dom, pt_base, struct_va + field_offset).await?;

    if let Some(pa) = pa {
        let val = dom.send(ReadPhysical::new(pa, field_sz)).await?;

        return Ok(Some(val));
    }
    Ok(None)
}

async fn read_kptr(
    dom: &kvmi::Domain,
    symbol: &str,
    kernel_base_va: u64,
    pt_base: u64,
    profile: &RekallProfile,
) -> Result<Option<u64>> {
    let ptr_rva = crate::get_ksymbol_offset(profile, symbol)?;
    let ptr_pa = translate_v2p(dom, pt_base, kernel_base_va + ptr_rva).await?;
    if let Some(ptr_pa) = ptr_pa {
        let val = dom.send(ReadPhysical::new(ptr_pa, PTR_SZ)).await?;
        let val = u64::from_ne_bytes(val[..].try_into().unwrap());
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

pub async fn get_system_page_table(
    dom: Arc<kvmi::Domain>,
    kernel_base_va: u64,
    pt_base: u64,
    profile: &RekallProfile,
) -> Result<Option<u64>> {
    let dtb_rva = crate::get_struct_field_offset(profile, KPROCESS, "DirectoryTableBase")?;
    let flink_rva = crate::get_struct_field_offset(profile, "_LIST_ENTRY", "Flink")?;
    let blink_rva = crate::get_struct_field_offset(profile, "_LIST_ENTRY", "Blink")?;
    let name_rva = crate::get_struct_field_offset(profile, EPROCESS, "ImageFileName")?;

    debug!("trying to get page table base from PsInitialSystemProcess");
    let ptb = process::by_ps_init_sys(&dom, kernel_base_va, pt_base, profile, dtb_rva).await?;
    if ptb.is_some() {
        return Ok(ptb);
    }

    debug!("trying to get page table base from process list");
    let process_head = kernel_base_va + crate::get_ksymbol_offset(profile, "PsActiveProcessHead")?;
    debug!("process_head: 0x{:x?}", process_head);
    let ptb = process::process_list_traversal(
        Arc::clone(&dom),
        process_head,
        pt_base,
        profile,
        dtb_rva,
        flink_rva,
        blink_rva,
    )
    .await?;
    if ptb.is_some() {
        return Ok(ptb);
    }

    debug!("trying to get page table base by scanning");
    let max_gfn = dom.send(GetMaxGfn).await?;
    debug!("max_gfn: 0x{:?}", max_gfn);
    let ptb = by_physical_mem_scan(
        &dom,
        profile,
        0x10_0000..max_gfn << PAGE_SHIFT,
        name_rva,
        dtb_rva,
        flink_rva,
        blink_rva,
    )
    .await?;

    Ok(ptb)
}

#[allow(clippy::trivial_regex)]
pub async fn by_physical_mem_scan(
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
    let major_rva = crate::get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMajorVersion")?;
    let minor_rva = crate::get_struct_field_offset(profile, KUSER_SHARED_DATA, "NtMinorVersion")?;

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
            });

        for (_offset, dtb, flink) in matches {
            debug!("verifying dtb: 0x{:x?}", dtb);
            if !verify_by_user_shared(dom, major_rva, minor_rva, addr_range.end, dtb).await? {
                debug!("dtb: 0x{:x?} filtered by user shared data", dtb);
                continue;
            }
            if !verify_by_thread_list(dom, dtb, flink, flink_rva, blink_rva).await? {
                debug!("dtb: 0x{:x?} filtered by thread list reflection test", dtb);
                continue;
            }
            return Ok(Some(dtb));
        }

        prev_page = page;
    }
    Ok(None)
}

pub async fn verify_by_user_shared(
    dom: &kvmi::Domain,
    major_rva: u64,
    minor_rva: u64,
    max_paddr: u64,
    dtb: u64,
) -> Result<bool> {
    debug!("verifying by user shared");
    let major_pa = translate_v2p(dom, dtb, KI_USER_SHARED_DATA_PTR + major_rva).await?;
    let minor_pa = translate_v2p(dom, dtb, KI_USER_SHARED_DATA_PTR + minor_rva).await?;
    match (major_pa, minor_pa) {
        (Some(major_pa), Some(minor_pa)) => {
            if major_pa >= max_paddr || minor_pa >= max_paddr {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }

    let major =
        read_struct_field(dom, KI_USER_SHARED_DATA_PTR, major_rva, LLP64_ULONG_SZ, dtb).await?;
    let minor =
        read_struct_field(dom, KI_USER_SHARED_DATA_PTR, minor_rva, LLP64_ULONG_SZ, dtb).await?;
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

pub async fn verify_by_thread_list(
    dom: &kvmi::Domain,
    dtb: u64,
    flink: u64,
    flink_rva: u64,
    blink_rva: u64,
) -> Result<bool> {
    debug!("verifying by thread list");
    let blink = read_struct_field(&dom, flink, blink_rva, PTR_SZ, dtb).await?;
    if let Some(blink) = blink {
        let blink = u64::from_ne_bytes(blink[..].try_into().unwrap());

        let flink_test = read_struct_field(&dom, blink, flink_rva, PTR_SZ, dtb).await?;
        if let Some(flink_test) = flink_test {
            let flink_test = u64::from_ne_bytes(flink_test[..].try_into().unwrap());
            let passed = flink == flink_test;
            return Ok(passed);
        }
    }
    Ok(false)
}

pub fn get_kernel_va_from(msrs: &HashMap<u32, u64>, profile: &RekallProfile) -> Result<u64> {
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

pub async fn find_kernel_addr(
    dom: &kvmi::Domain,
    reply: &GetRegistersReply,
    profile: &RekallProfile,
) -> Result<(u64, u64, u64)> {
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
    let kernel_base_pa = translate_v2p(dom, pt_base, kernel_base_va).await?;

    info!("kernel base physical address: 0x{:x?}", kernel_base_pa);
    let kernel_base_pa = kernel_base_pa.ok_or(Error::KernelPAddr)?;
    Ok((kernel_base_va, kernel_base_pa, pt_base))
}
