use crate::memory::address_space::{IA32eAddrT, IA32eVirtual};
use crate::memory::list::ForwardIter;
use crate::{Error, RekallProfile, Result};
use crate::{FLINK, LIST_ENTRY, PTR_SZ};

use std::convert::TryInto;

use async_std::prelude::*;

pub async fn get_sys_module_list<'a, 'b>(
    k_vspace: &'a IA32eVirtual,
    kernel_base: IA32eAddrT,
    profile: &'b RekallProfile,
) -> Result<ForwardIter<'a>> {
    let head_ptr = profile.get_ksymbol_offset("PsLoadedModuleList")?;
    let flink_rva = profile.get_struct_field_offset(LIST_ENTRY, FLINK)?;

    let head = k_vspace.read(kernel_base + head_ptr, PTR_SZ).await?;
    let head = head.ok_or(Error::InvalidVAddr)?;
    let head = u64::from_ne_bytes(head[..].try_into().unwrap());

    let iter = ForwardIter::new(k_vspace, head, flink_rva);
    Ok(iter)
}

pub async fn find_module(
    k_vspace: &IA32eVirtual,
    profile: &RekallProfile,
    kernel_base_va: IA32eAddrT,
    expect_name: &str,
) -> Result<IA32eAddrT> {
    let name_rva = profile.get_struct_field_offset("_KLDR_DATA_TABLE_ENTRY", "BaseDllName")?;
    let base_rva = profile.get_struct_field_offset("_KLDR_DATA_TABLE_ENTRY", "DllBase")?;

    let mut iter = get_sys_module_list(k_vspace, kernel_base_va, profile).await?;
    while let Some(module_ptr) = iter.next().await {
        let name = super::read_utf16(k_vspace, module_ptr + name_rva).await?;
        if name == expect_name {
            let base = k_vspace.read(module_ptr + base_rva, PTR_SZ).await?;
            return if let Some(base) = base {
                let base = IA32eAddrT::from_ne_bytes(base[..].try_into().unwrap());
                Ok(base)
            } else {
                Err(Error::InvalidVAddr)
            };
        }
    }
    Err(Error::NotFound(format!("module {}", expect_name)))
}
