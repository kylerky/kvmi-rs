use crate::memory::address_space::{IA32eAddrT, IA32eVirtual};
use crate::{Error, RekallProfile, Result, PAGE_SHIFT, PTR_SZ};

use std::convert::TryInto;

const PTR_SHIFT: u32 = PTR_SZ.trailing_zeros();
const HANDLE_STEP: u32 = 4;
const HANDLE_STEP_SHIFT: u32 = HANDLE_STEP.trailing_zeros();

const LEVEL_MASK: IA32eAddrT = 7;

const OBJECT_PTR_RSHIFT: u32 = 20;
const OBJECT_PTR_LSHIFT: u32 = 4;
const OBJECT_PTR_PREFIX: IA32eAddrT = 0xffff_0000_0000_0000;

pub async fn get_obj_by(
    v_space: &IA32eVirtual,
    handle: u64,
    process: IA32eAddrT,
    profile: &RekallProfile,
) -> Result<IA32eAddrT> {
    let handle_entry_sz = profile.get_struct_size("_HANDLE_TABLE_ENTRY")?;
    let handle_entry_shift = handle_entry_sz.trailing_zeros();

    let (table_ptr, level) = get_handle_table_from(v_space, process, profile).await?;

    find_obj(v_space, table_ptr, handle, level, handle_entry_shift).await
}

async fn find_obj(
    v_space: &IA32eVirtual,
    mut table_ptr: IA32eAddrT,
    handle: u64,
    mut level: u64,
    entry_shift: u32,
) -> Result<IA32eAddrT> {
    loop {
        let offset = match level {
            2 => {
                handle >> (PAGE_SHIFT - entry_shift + HANDLE_STEP_SHIFT + PAGE_SHIFT - PTR_SHIFT)
                    << PTR_SHIFT
            }
            1 => {
                let mask_shift = PAGE_SHIFT - PTR_SHIFT;
                let mask = !(!0 << mask_shift);

                let idx = handle >> (PAGE_SHIFT - entry_shift + HANDLE_STEP_SHIFT);
                let idx = idx & mask;
                idx << PTR_SHIFT
            }
            0 => {
                let mask_shift = PAGE_SHIFT - entry_shift;
                let mask = !(!0 << mask_shift);

                let mut idx = handle >> HANDLE_STEP_SHIFT;
                idx &= mask;
                let offset = idx << entry_shift;
                let ptr = v_space
                    .read(table_ptr + offset, PTR_SZ)
                    .await?
                    .ok_or(Error::InvalidVAddr)?;
                let mut ptr = IA32eAddrT::from_ne_bytes(ptr[..].try_into().unwrap());

                ptr = ptr >> OBJECT_PTR_RSHIFT << OBJECT_PTR_LSHIFT;
                ptr |= OBJECT_PTR_PREFIX;

                return Ok(ptr);
            }
            _ => {
                return Err(Error::Unsupported(String::from(
                    "Unsupported number of levels of handle table",
                )))
            }
        };

        // read the table ptr
        let new_ptr = v_space
            .read(table_ptr + offset, PTR_SZ)
            .await?
            .ok_or(Error::InvalidVAddr)?;
        let new_ptr = IA32eAddrT::from_ne_bytes(new_ptr[..].try_into().unwrap());
        // into the next level
        table_ptr = new_ptr;
        level -= 1;
    }
}

async fn get_handle_table_from(
    v_space: &IA32eVirtual,
    process: IA32eAddrT,
    profile: &RekallProfile,
) -> Result<(IA32eAddrT, u64)> {
    let table_struct_rva = profile.get_struct_field_offset("_EPROCESS", "ObjectTable")?;
    let table_code_rva = profile.get_struct_field_offset("_HANDLE_TABLE", "TableCode")?;

    let table_struct_ptr = v_space
        .read(process + table_struct_rva, PTR_SZ)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let table_struct_ptr = IA32eAddrT::from_ne_bytes(table_struct_ptr[..].try_into().unwrap());

    let table_code = v_space
        .read(table_struct_ptr + table_code_rva, PTR_SZ)
        .await?
        .ok_or(Error::InvalidVAddr)?;
    let table_code = IA32eAddrT::from_ne_bytes(table_code[..].try_into().unwrap());
    let level = table_code & LEVEL_MASK;
    let table_ptr = table_code & !LEVEL_MASK;

    Ok((table_ptr, level))
}
