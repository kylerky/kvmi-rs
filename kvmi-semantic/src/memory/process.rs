use crate::{RekallProfile, Result};
use crate::{EPROCESS, PAGE_SHIFT, PTR_SZ};

use log::debug;

use async_std::sync::{self, Arc, Receiver, Sender};
use async_std::task;

use std::collections::HashSet;
use std::convert::TryInto;

const SYSTEM_PID: u64 = 4;

type PSChanT = Result<u64>;
pub async fn by_ps_init_sys(
    dom: &kvmi::Domain,
    kernel_base_va: u64,
    pt_base: u64,
    profile: &RekallProfile,
    dtb_rva: u64,
) -> Result<Option<u64>> {
    if let Some(proc_va) = super::read_kptr(
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
            super::read_struct_field(dom, proc_va, dtb_rva, PTR_SZ, pt_base).await?
        {
            let page_table_ptr = u64::from_ne_bytes(page_table_ptr[..].try_into().unwrap());
            return Ok(Some(page_table_ptr));
        }
    }
    Ok(None)
}

pub async fn by_eprocess_list_traversal(
    dom: Arc<kvmi::Domain>,
    head: u64,
    pt_base: u64,
    profile: &RekallProfile,
    dtb_rva: u64,
    flink_rva: u64,
    blink_rva: u64,
) -> Result<Option<u64>> {
    let processes = get_process_list_from(
        Arc::clone(&dom),
        head,
        pt_base,
        profile,
        flink_rva,
        blink_rva,
    )?;
    let pid_rva = crate::get_struct_field_offset(profile, EPROCESS, "UniqueProcessId")?;
    // skip the list head
    processes.recv().await;
    while let Some(process) = processes.recv().await {
        let process = process?;
        if let Some(pid) = super::read_struct_field(&dom, process, pid_rva, PTR_SZ, pt_base).await?
        {
            let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
            if pid == SYSTEM_PID {
                let dtb = super::read_struct_field(&dom, process, dtb_rva, PTR_SZ, pt_base).await?;
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

pub fn get_process_list_from(
    dom: Arc<kvmi::Domain>,
    head: u64,
    pt_base: u64,
    profile: &RekallProfile,
    flink_rva: u64,
    blink_rva: u64,
) -> Result<Receiver<PSChanT>> {
    let links_rva = crate::get_struct_field_offset(profile, EPROCESS, "ActiveProcessLinks")?;

    let (tx, rx) = sync::channel(1);
    task::spawn(async move {
        traverse_process_list(dom, head, pt_base, flink_rva, blink_rva, links_rva, tx).await;
    });

    Ok(rx)
}

pub async fn traverse_process_list(
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
        let links = match super::read_struct_field(&dom, link, 0, PTR_SZ * 2, pt_base).await {
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
