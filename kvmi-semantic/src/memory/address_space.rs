#[cfg(test)]
mod tests;

mod cache;
use cache::StalePageCache as PageCache;

use cfg_if::cfg_if;

use crate::{Error, Result};

use async_std::sync::{Arc, Mutex, RwLock};

use std::collections::HashMap;
use std::convert::TryInto;

use kvmi::message::WritePhysical;

// [12..52] bit of the entry
const ENTRY_POINTER_MASK: u64 = (!0u64) << 24 >> 12;
const PG_MASK: u64 = 1u64 << 7;
const P_MASK: u64 = 1;
const VA_MASK: u64 = 0xff8;
const CANON_MASK: u64 = 0xffff_8000_0000_0000;

pub type PhysicalAddrT = u64;
const PADDR_OFFSET: PhysicalAddrT = 0xfff;

const PHYSICAL_PAGE_SZ: PhysicalAddrT = 1 << 12;

pub type IA32eAddrT = u64;

pub trait AddressSpace {
    type AddrT;
    // TODO
    //     async fn read(&mut self, addr: Self::AddrT, sz: usize) -> Result<Option<Vec<u8>>>;
    //     async fn write(&mut self, addr: Self::AddrT, data: Vec<u8>) -> Result<Option<()>>;
}

cfg_if! {
    if #[cfg(not(test))] {
        use kvmi::Domain;
        pub use kvmi_physical::*;
    } else {
        use tests::MockDomain as Domain;
        pub use tests::MockKVMIPhysical as KVMIPhysical;
    }
}

#[allow(dead_code)]
mod kvmi_physical {
    use super::*;
    pub struct KVMIPhysical {
        dom: Domain,
        cache: Mutex<PageCache>,
    }

    impl AddressSpace for KVMIPhysical {
        type AddrT = PhysicalAddrT;
    }

    impl KVMIPhysical {
        pub fn new(dom: Domain) -> Self {
            Self {
                dom,
                cache: Mutex::new(PageCache::new()),
            }
        }

        pub fn get_dom(&self) -> &Domain {
            &self.dom
        }

        pub async fn read(&self, addr: PhysicalAddrT, sz: usize) -> Result<Vec<u8>> {
            let mut cache = self.cache.lock().await;
            cache.read(&self.dom, addr, sz).await
        }

        pub async fn write(&self, addr: PhysicalAddrT, data: Vec<u8>) -> Result<()> {
            Self::validate(addr, data.len())?;

            self.evict(addr).await?;

            self.dom.send(WritePhysical::new(addr, data)).await?;
            Ok(())
        }

        pub async fn evict(&self, addr: PhysicalAddrT) -> Result<()> {
            let mut cache = self.cache.lock().await;
            cache.remove(&self.dom, addr).await
        }

        pub async fn flush(&self) -> Result<()> {
            let mut cache = self.cache.lock().await;
            cache.flush(&self.dom).await
        }

        // validate if the access is across page boundary
        fn validate(addr: PhysicalAddrT, sz: usize) -> Result<()> {
            let offset = addr & PADDR_OFFSET;
            if offset + sz as PhysicalAddrT > PHYSICAL_PAGE_SZ {
                Err(Error::PageBoundary)
            } else {
                Ok(())
            }
        }
    }

    impl From<Domain> for KVMIPhysical {
        fn from(dom: Domain) -> Self {
            Self::new(dom)
        }
    }
}

#[derive(Clone)]
pub struct IA32eVirtual {
    base: Arc<KVMIPhysical>,
    pub(crate) ptb: PhysicalAddrT,
    cache: Arc<RwLock<IA32eCache>>,
}

impl AddressSpace for IA32eVirtual {
    type AddrT = IA32eAddrT;
}

impl IA32eVirtual {
    pub fn new(base: Arc<KVMIPhysical>, ptb: PhysicalAddrT) -> Self {
        Self {
            base,
            ptb,
            cache: Arc::new(RwLock::new(IA32eCache::new())),
        }
    }

    pub(crate) fn set_ptb(&mut self, ptb: PhysicalAddrT) {
        self.ptb = ptb;
    }

    pub fn get_ptb(&self) -> PhysicalAddrT {
        self.ptb
    }

    pub fn get_base(&self) -> &Arc<KVMIPhysical> {
        &self.base
    }

    pub async fn read(&self, v_addr: IA32eAddrT, sz: usize) -> Result<Vec<u8>> {
        let p_addr = self.lookup(v_addr).await?;
        self.base.read(p_addr, sz).await
    }

    pub async fn write(&self, v_addr: IA32eAddrT, data: Vec<u8>) -> Result<()> {
        let p_addr = self.lookup(v_addr).await?;
        self.base.write(p_addr, data).await
    }

    pub async fn lookup(&self, v_addr: IA32eAddrT) -> Result<PhysicalAddrT> {
        if let Some((addr, level)) = self.cache.read().await.lookup(v_addr).await {
            let offset = level * 9 + 3;
            let mask = (!0) << offset;
            let res = (addr & mask) | (v_addr & (!mask));
            return Ok(res);
        }
        let (p_addr, level) = self.translate_v2p(v_addr).await?;
        let offset = level * 9 + 3;
        let mask = (!0) << offset;
        self.cache
            .write()
            .await
            .insert(v_addr, level, p_addr & mask);
        Ok(p_addr)
    }

    pub fn is_canonical(v_addr: IA32eAddrT) -> bool {
        match v_addr & CANON_MASK {
            0 | CANON_MASK => true,
            _ => false,
        }
    }

    pub async fn flush(&self) {
        self.cache.write().await.flush()
    }

    async fn translate_v2p(&self, v_addr: IA32eAddrT) -> Result<(PhysicalAddrT, u32)> {
        let mut base = self.ptb;
        let mut level: u32 = 4;
        loop {
            let offset = level * 9;
            // table lookup
            let v_addr_shift = (v_addr >> offset) & VA_MASK;
            let entry_addr = base | v_addr_shift;

            let entry = self.base.read(entry_addr, 8).await?;
            let entry = u64::from_ne_bytes(entry[..].try_into().unwrap());

            // check entry
            let (paddr, pg, present) = Self::read_entry(entry);
            if !present {
                return Err(Error::InvalidVAddr);
            }

            // add offset in a page frame
            if pg || level == 1 {
                let mask = (!0) << (offset + 3);
                let addr = (paddr & mask) | (v_addr & !mask);
                return Ok((addr, level));
            }
            level -= 1;
            base = paddr;
        }
    }

    // Returns (gpa, PG, present)
    fn read_entry(entry: u64) -> (PhysicalAddrT, bool, bool) {
        let present = (entry & P_MASK) != 0;
        if present {
            let pg = (entry & PG_MASK) != 0;
            (entry & ENTRY_POINTER_MASK, pg, present)
        } else {
            (0, false, present)
        }
    }
}

#[derive(Clone, Default)]
struct IA32eCache {
    cache: HashMap<IA32eAddrT, PhysicalAddrT>,
}

impl IA32eCache {
    const MAX_LEVEL: u32 = 4;
    fn new() -> Self {
        Self::default()
    }

    fn get_key(v_addr: IA32eAddrT, level: u32) -> IA32eAddrT {
        let offset = level * 9 + 3;
        let key_len = (Self::MAX_LEVEL - level + 1) * 9;
        let mask = !(!0 << key_len);
        (v_addr >> offset) & mask
    }

    async fn lookup(&self, v_addr: IA32eAddrT) -> Option<(PhysicalAddrT, u32)> {
        (1..Self::MAX_LEVEL).find_map(|level| {
            let key = Self::get_key(v_addr, level);
            self.cache.get(&key).map(|k| (*k, level))
        })
    }

    fn insert(
        &mut self,
        v_addr: IA32eAddrT,
        level: u32,
        p_addr: PhysicalAddrT,
    ) -> Option<PhysicalAddrT> {
        self.cache.insert(Self::get_key(v_addr, level), p_addr)
    }

    fn flush(&mut self) {
        self.cache.clear();
    }
}
