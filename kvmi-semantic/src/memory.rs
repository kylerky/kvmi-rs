use super::Result;

use kvmi::message::ReadPhysical;

use std::convert::TryInto;

use log::debug;

// [12..52] bit of the entry
const ENTRY_POINTER_MASK: u64 = (!0u64) << 24 >> 12;
const PG_MASK: u64 = 1u64 << 7;
const P_MASK: u64 = 1;
const VA_MASK: u64 = 0xff8;

pub async fn translate_v2p(
    dom: &mut kvmi::Domain,
    table_base: u64,
    v_addr: u64,
) -> Result<Option<u64>> {
    let mut base = table_base;
    let mut level: u32 = 4;
    debug!("v_addr: 0x{:x?}", v_addr);
    let result = loop {
        let offset = level * 9;
        // table lookup
        let v_addr_shift = (v_addr >> offset) & VA_MASK;
        let entry_addr = base | v_addr_shift;
        debug!("level: {}, entry addr: 0x{:x?}", level, entry_addr);
        let entry = dom.send(ReadPhysical::new(entry_addr, 8)).await?;
        let entry = u64::from_ne_bytes(entry[..].try_into().unwrap());
        debug!("Page entry: 0x{:x?}", entry);

        // check entry
        let (paddr, pg, present) = read_entry(entry);
        if !present {
            break None;
        }

        level -= 1;
        // add offset in a page frame
        if pg || level == 0 {
            let mask = (!0) << offset;
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
