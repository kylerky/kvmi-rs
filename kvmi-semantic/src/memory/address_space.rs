#[cfg(test)]
mod tests;

use cfg_if::cfg_if;

use crate::{Error, Result};

use async_std::sync::{Arc, Mutex, RwLock};

use std::collections::HashMap;
use std::convert::TryInto;

use kvmi::message::{ReadPhysical, SetPageAccess, SetPageWriteBitmap, WritePhysical};
use kvmi::{BitmapEntryBuilder, PageAccessEntryBuilder, PageWriteBitmap};

use futures::future::{BoxFuture, FutureExt};

use lru::LruCache;

use log::debug;

// [12..52] bit of the entry
const ENTRY_POINTER_MASK: u64 = (!0u64) << 24 >> 12;
const PG_MASK: u64 = 1u64 << 7;
const P_MASK: u64 = 1;
const VA_MASK: u64 = 0xff8;
const CANON_MASK: u64 = 0xffff_8000_0000_0000;

pub type PhysicalAddrT = u64;
const PHYSICAL_PAGE_SZ: PhysicalAddrT = 1 << 12;
const ADDR_MASK: PhysicalAddrT = PHYSICAL_PAGE_SZ - 1;
const ADDR_PAGE: PhysicalAddrT = !ADDR_MASK;

const SUBPAGE_SHIFT: u32 = 7;
const SUBPAGE_SZ: PhysicalAddrT = 1 << SUBPAGE_SHIFT;
const SUBPAGE_OFFSET: PhysicalAddrT = SUBPAGE_SZ - 1;
const SUBPAGE_KEY: PhysicalAddrT = !SUBPAGE_OFFSET;

const VADDR_OFFSET_MASK: IA32eAddrT = 0xfff;
const V_PAGE_SZ: IA32eAddrT = 1 << 12;

pub type IA32eAddrT = u64;

pub trait AddressSpace {
    type AddrT;
    // TODO
    //     async fn read(&mut self, addr: Self::AddrT, sz: usize) -> Result<Option<Vec<u8>>>;
    //     async fn write(&mut self, addr: Self::AddrT, data: Vec<u8>) -> Result<Option<()>>;
}

cfg_if! {
    if #[cfg(test)] {
        pub use tests::MockKVMIPhysical as KVMIPhysical;
    } else {
        pub use kvmi_physical::*;
    }
}

const CACHE_CAP: usize = 1 << 23;
#[allow(dead_code)]
mod kvmi_physical {
    use super::*;
    pub struct KVMIPhysical {
        dom: kvmi::Domain,
        cache: Mutex<Cache>,
    }

    struct Cache {
        subpages: LruCache<PhysicalAddrT, Vec<u8>>,
        bitmaps: HashMap<PhysicalAddrT, PageWriteBitmap>,
    }

    impl AddressSpace for KVMIPhysical {
        type AddrT = PhysicalAddrT;
    }

    impl KVMIPhysical {
        pub fn new(dom: kvmi::Domain) -> Self {
            Self {
                dom,
                cache: Mutex::new(Cache {
                    subpages: LruCache::new(CACHE_CAP),
                    bitmaps: HashMap::new(),
                }),
            }
        }

        pub fn get_dom(&self) -> &kvmi::Domain {
            &self.dom
        }

        pub async fn read(&self, addr: PhysicalAddrT, sz: usize) -> Result<Vec<u8>> {
            if sz == 0 {
                return Ok(vec![]);
            }

            let key = addr & SUBPAGE_KEY;
            let offset = (addr & SUBPAGE_OFFSET) as usize;

            let subpages_num = (offset + sz - 1) / SUBPAGE_SZ as usize;
            debug!(
                "key: 0x{:x?}, offset: 0x{:x?}, num: 0x{:x?}",
                key, offset, subpages_num
            );
            match subpages_num {
                0 => self.read_within_subpage(key, offset, sz).await,
                _ => {
                    let mut res = self
                        .read_within_subpage(key, offset, PHYSICAL_PAGE_SZ as usize - offset)
                        .await?;

                    for i in 1..subpages_num as u64 {
                        debug!("key: 0x{:x?}", key + i * SUBPAGE_SZ);
                        let mut v = self
                            .read_within_subpage(key + i * SUBPAGE_SZ, 0, SUBPAGE_SZ as usize)
                            .await?;
                        res.append(&mut v);
                    }

                    let remaining = offset + sz - subpages_num * SUBPAGE_SZ as usize;
                    debug!("remaining: 0x{:x?}", remaining);
                    let mut v = self
                        .read_within_subpage(key + subpages_num as u64 * SUBPAGE_SZ, 0, remaining)
                        .await?;
                    res.append(&mut v);
                    Ok(res)
                }
            }
        }

        async fn read_within_subpage(
            &self,
            key: PhysicalAddrT,
            offset: usize,
            sz: usize,
        ) -> Result<Vec<u8>> {
            let mut cache = self.cache.lock().await;
            match cache.subpages.get(&key) {
                Some(vec) => {
                    debug!("cache hit");
                    Ok(vec[offset..offset + sz].to_vec())
                }
                None => {
                    debug!("cache missed");
                    let page = key & ADDR_PAGE;
                    let mut bitmap = cache
                        .bitmaps
                        .get(&page)
                        .map(|m| *m)
                        .unwrap_or_else(|| PageWriteBitmap::default());

                    let pos = (key & ADDR_MASK) >> SUBPAGE_SHIFT;
                    bitmap.clear(pos);

                    // TODO: switch to SPP
                    let mut msg = SetPageWriteBitmap::new();
                    let mut builder = BitmapEntryBuilder::new(page);
                    builder.bitmap(bitmap);
                    // let mut msg = SetPageAccess::new();
                    // let mut builder = PageAccessEntryBuilder::new(page);
                    // builder.set_read().set_execute();
                    msg.push(builder.build());

                    self.dom.send(msg).await?;
                    cache.bitmaps.insert(page, bitmap);

                    let data = self.dom.send(ReadPhysical::new(key, SUBPAGE_SZ)).await?;
                    let ret = data[offset..offset + sz].to_vec();
                    cache.subpages.put(key, data);
                    Ok(ret)
                }
            }
        }

        pub async fn write(&self, addr: PhysicalAddrT, data: Vec<u8>) -> Result<()> {
            Self::validate(addr, data.len())?;

            self.invalidate(addr).await?;

            self.dom.send(WritePhysical::new(addr, data)).await?;
            Ok(())
        }

        pub async fn invalidate(&self, addr: PhysicalAddrT) -> Result<()> {
            debug!("invalidate: 0x{:x?}", addr);
            let key = addr & SUBPAGE_KEY;
            let page = addr & ADDR_PAGE;

            let mut cache = self.cache.lock().await;
            let bitmap = cache.bitmaps.get(&page).map(|m| *m);
            match bitmap {
                None => return Ok(()),
                Some(mut bitmap) => {
                    let pos = (key & ADDR_MASK) >> SUBPAGE_SHIFT;
                    bitmap.set(pos);
                    debug!("bitmap: 0x{:x?}", bitmap);

                    // TODO: switch to SPP
                    let mut msg = SetPageWriteBitmap::new();
                    let mut builder = BitmapEntryBuilder::new(page);
                    builder.bitmap(bitmap);
                    msg.push(builder.build());
                    self.dom.send(msg).await?;
                    if bitmap == PageWriteBitmap::default() {
                        // let mut msg = SetPageAccess::new();
                        // let mut builder = PageAccessEntryBuilder::new(page);
                        // builder.set_read().set_write().set_execute();
                        // msg.push(builder.build());
                        // self.dom.send(msg).await?;

                        cache.bitmaps.remove(&page);
                    } else {
                        cache.bitmaps.insert(page, bitmap);
                    }
                    cache.subpages.pop(&key);
                }
            }
            Ok(())
        }

        // validate if the access is across page boundary
        fn validate(addr: PhysicalAddrT, sz: usize) -> Result<()> {
            let offset = addr & ADDR_MASK;
            if offset + sz as PhysicalAddrT > PHYSICAL_PAGE_SZ {
                Err(Error::PageBoundary)
            } else {
                Ok(())
            }
        }

        fn is_cross_cache_line(offset: PhysicalAddrT, sz: usize) -> bool {
            (offset + sz as PhysicalAddrT) > SUBPAGE_SZ
        }
    }

    impl From<kvmi::Domain> for KVMIPhysical {
        fn from(dom: kvmi::Domain) -> Self {
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

    pub async fn read(&self, v_addr: IA32eAddrT, sz: usize) -> Result<Option<Vec<u8>>> {
        let p_addr = self.lookup(v_addr).await?;
        if let Some(p_addr) = p_addr {
            let res = self.base.read(p_addr, sz).await;
            if let Err(Error::PageBoundary) = res {
                return self.read_across_boundary(v_addr, sz).await;
            }
            res.map(Some)
        } else {
            Ok(None)
        }
    }

    fn read_across_boundary(
        &self,
        v_addr: IA32eAddrT,
        sz: usize,
    ) -> BoxFuture<Result<Option<Vec<u8>>>> {
        async move {
            let offset = v_addr & VADDR_OFFSET_MASK;
            let first_sz = (V_PAGE_SZ - offset) as usize;
            let second_sz = sz - first_sz;
            let second_addr = (v_addr & (!VADDR_OFFSET_MASK)) + V_PAGE_SZ;

            let first = self.read(v_addr, first_sz).await?;
            if let Some(mut first) = first {
                let second = self.read(second_addr, second_sz).await?;
                if let Some(mut second) = second {
                    first.append(&mut second);
                    return Ok(Some(first));
                }
            }
            Ok(None)
        }
        .boxed()
    }

    pub async fn write(&self, v_addr: IA32eAddrT, data: Vec<u8>) -> Result<Option<()>> {
        let p_addr = self.lookup(v_addr).await?;
        if let Some(p_addr) = p_addr {
            self.base.write(p_addr, data).await.map(|_| Some(()))
        } else {
            Ok(None)
        }
    }

    pub async fn lookup(&self, v_addr: IA32eAddrT) -> Result<Option<PhysicalAddrT>> {
        if let Some((addr, level)) = self.cache.read().await.lookup(v_addr).await {
            let offset = level * 9 + 3;
            let mask = (!0) << offset;
            let res = (addr & mask) | (v_addr & (!mask));
            return Ok(Some(res));
        }
        match self.translate_v2p(v_addr).await? {
            None => Ok(None),
            Some((p_addr, level)) => {
                let offset = level * 9 + 3;
                let mask = (!0) << offset;
                self.cache
                    .write()
                    .await
                    .insert(v_addr, level, p_addr & mask);
                Ok(Some(p_addr))
            }
        }
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

    async fn translate_v2p(&self, v_addr: IA32eAddrT) -> Result<Option<(PhysicalAddrT, u32)>> {
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

            // add offset in a page frame
            if pg || level == 1 {
                let mask = (!0) << (offset + 3);
                let addr = (paddr & mask) | (v_addr & !mask);
                break Some((addr, level));
            }
            level -= 1;
            base = paddr;
        };
        Ok(result)
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
