use super::address_space::IA32eVirtual;
use super::CR3_MASK;
use crate::{RekallProfile, Result};
use crate::{BLINK, EPROCESS, FLINK, LIST_ENTRY, PTR_SZ};

use log::debug;

use async_std::sync::{self, Receiver, Sender};
use async_std::task::{self, JoinHandle};

use std::collections::HashSet;
use std::convert::TryInto;
use std::future::Future;
use std::mem;

use futures::future::FutureExt;
use futures::select;
use futures::stream::StreamExt;

const SYSTEM_PID: u64 = 4;

pub type PSChanT = Result<u64>;
pub async fn by_ps_init_sys(
    v_space: &IA32eVirtual,
    kernel_base_va: u64,
    profile: &RekallProfile,
    dtb_rva: u64,
) -> Result<Option<u64>> {
    if let Some(proc_va) =
        super::read_kptr(v_space, "PsInitialSystemProcess", kernel_base_va, profile).await?
    {
        debug!("System virtual address: 0x{:x?}", proc_va);
        if let Some(page_table_ptr) = v_space.read(proc_va + dtb_rva, PTR_SZ).await? {
            let page_table_ptr = u64::from_ne_bytes(page_table_ptr[..].try_into().unwrap());
            return Ok(Some(page_table_ptr & CR3_MASK));
        }
    }
    Ok(None)
}

pub async fn process_list_traversal<F, FR>(
    v_space: IA32eVirtual,
    fut: F,
    head: u64,
    profile: &RekallProfile,
) -> Result<FR::Output>
where
    F: FnOnce(Receiver<PSChanT>) -> FR,
    FR: Future,
{
    let (shutdown, sd_rx) = sync::channel(1);
    let (processes, handle) = get_process_list_from(v_space, head, sd_rx, profile)?;

    let result = fut(processes).await;

    mem::drop(shutdown);
    handle.await;
    Ok(result)
}

pub async fn by_eprocess_list_traversal(
    v_space: &IA32eVirtual,
    processes: Receiver<PSChanT>,
    profile: &RekallProfile,
    dtb_rva: u64,
) -> Result<Option<u64>> {
    let pid_rva = crate::get_struct_field_offset(profile, EPROCESS, "UniqueProcessId")?;
    // skip the list head
    processes.recv().await;
    while let Some(process) = processes.recv().await {
        let process = process?;
        if let Some(pid) = v_space.read(process + pid_rva, PTR_SZ).await? {
            let pid = u64::from_ne_bytes(pid[..].try_into().unwrap());
            if pid == SYSTEM_PID {
                // let dtb = super::read_struct_field(dom, process, dtb_rva, PTR_SZ, pt_base).await?;
                let dtb = v_space.read(process + dtb_rva, PTR_SZ).await?;
                if let Some(dtb) = dtb {
                    let dtb = u64::from_ne_bytes(dtb[..].try_into().unwrap());
                    // sanity check of dtb
                    if dtb > 0 {
                        return Ok(Some(dtb & CR3_MASK));
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn get_process_list_from(
    v_space: IA32eVirtual,
    head: u64,
    sd_rx: Receiver<()>,
    profile: &RekallProfile,
) -> Result<(Receiver<PSChanT>, JoinHandle<()>)> {
    let flink_rva = crate::get_struct_field_offset(profile, LIST_ENTRY, FLINK)?;
    let blink_rva = crate::get_struct_field_offset(profile, LIST_ENTRY, BLINK)?;
    let links_rva = crate::get_struct_field_offset(profile, EPROCESS, "ActiveProcessLinks")?;

    let (tx, rx) = sync::channel(4);

    let handle = task::spawn(async move {
        let mut sd_rx = sd_rx.fuse();
        select! {
            () = traverse_process_list(v_space, head, flink_rva, blink_rva, links_rva, tx).fuse() => (),
            _ = sd_rx.next() => (),
        };
    });

    Ok((rx, handle))
}

pub async fn traverse_process_list(
    v_space: IA32eVirtual,
    head: u64,
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
        let links = match v_space.read(link, PTR_SZ * 2).await {
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