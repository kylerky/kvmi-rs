use crate::Result;

use async_std::sync::Arc;

use std::convert::TryInto;

use kvmi::message::ReadPhysical;

// [12..52] bit of the entry
const ENTRY_POINTER_MASK: u64 = (!0u64) << 24 >> 12;
const PG_MASK: u64 = 1u64 << 7;
const P_MASK: u64 = 1;
const VA_MASK: u64 = 0xff8;

pub trait AddressSpace {
    type AddrT;
    // TODO
    //     async fn read(&mut self, addr: Self::AddrT, sz: usize) -> Result<Option<Vec<u8>>>;
    //     async fn write(&mut self, addr: Self::AddrT, data: Vec<u8>) -> Result<Option<()>>;
}

pub struct KVMIPhysical {
    dom: kvmi::Domain,
}

impl AddressSpace for KVMIPhysical {
    type AddrT = u64;
}

impl KVMIPhysical {
    pub fn new(dom: kvmi::Domain) -> Self {
        Self { dom }
    }

    pub fn get_dom(&self) -> &kvmi::Domain {
        &self.dom
    }

    pub async fn read(&self, addr: <Self as AddressSpace>::AddrT, sz: usize) -> Result<Vec<u8>> {
        let data = self.dom.send(ReadPhysical::new(addr, sz as u64)).await?;
        Ok(data)
    }

    pub async fn write(&self, addr: <Self as AddressSpace>::AddrT, data: Vec<u8>) -> Result<()> {
        Ok(())
    }
}

impl From<kvmi::Domain> for KVMIPhysical {
    fn from(dom: kvmi::Domain) -> Self {
        Self::new(dom)
    }
}

#[derive(Clone)]
pub struct IA32eVirtual {
    base: Arc<KVMIPhysical>,
    ptb: <KVMIPhysical as AddressSpace>::AddrT,
}

impl AddressSpace for IA32eVirtual {
    type AddrT = u64;
}

impl IA32eVirtual {
    pub fn new(base: Arc<KVMIPhysical>, ptb: <KVMIPhysical as AddressSpace>::AddrT) -> Self {
        Self { base, ptb }
    }

    pub fn get_ptb(&self) -> <Self as AddressSpace>::AddrT {
        self.ptb
    }

    pub fn get_base(&self) -> &Arc<KVMIPhysical> {
        &self.base
    }

    pub fn set_ptb(&mut self, ptb: <KVMIPhysical as AddressSpace>::AddrT) {
        self.ptb = ptb;
    }

    pub async fn read(
        &self,
        v_addr: <Self as AddressSpace>::AddrT,
        sz: usize,
    ) -> Result<Option<Vec<u8>>> {
        let p_addr = self.translate_v2p(v_addr).await?;
        if let Some(p_addr) = p_addr {
            self.base.read(p_addr, sz).await.map(Some)
        } else {
            Ok(None)
        }
    }

    pub async fn write(
        &self,
        v_addr: <Self as AddressSpace>::AddrT,
        data: Vec<u8>,
    ) -> Result<Option<()>> {
        let p_addr = self.translate_v2p(v_addr).await?;
        if let Some(p_addr) = p_addr {
            self.base.write(p_addr, data).await.map(|_| Some(()))
        } else {
            Ok(None)
        }
    }

    pub async fn translate_v2p(
        &self,
        v_addr: <Self as AddressSpace>::AddrT,
    ) -> Result<Option<<KVMIPhysical as AddressSpace>::AddrT>> {
        let mut base = self.ptb;
        let mut level: u32 = 4;
        let result = loop {
            let offset = level * 9;
            // table lookup
            let v_addr_shift = (v_addr >> offset) & VA_MASK;
            let entry_addr = base | v_addr_shift;

            let entry = self.base.read(entry_addr, 8).await?;
            let entry = u64::from_ne_bytes(entry[..].try_into().unwrap());

            // check entry
            let (paddr, pg, present) = Self::read_entry(entry);
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
    fn read_entry(entry: u64) -> (<KVMIPhysical as AddressSpace>::AddrT, bool, bool) {
        let present = (entry & P_MASK) != 0;
        if present {
            let pg = (entry & PG_MASK) != 0;
            (entry & ENTRY_POINTER_MASK, pg, present)
        } else {
            (0, false, present)
        }
    }
}
