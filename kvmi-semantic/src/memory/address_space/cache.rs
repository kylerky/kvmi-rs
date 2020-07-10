use super::{Domain, PhysicalAddrT};
use super::{PADDR_OFFSET, PHYSICAL_PAGE_SZ};

use kvmi::message::{ReadPhysical, SetPageAccess};
use kvmi::PageAccessEntryBuilder;

use lru::LruCache;

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

use crate::Result;

const CACHE_CAP: usize = 1 << 18;
const VOLATILE_TIMEOUT: Duration = Duration::from_millis(10);
const PADDR_KEY: PhysicalAddrT = !PADDR_OFFSET;

pub struct PageCache {
    pages: LruCache<PhysicalAddrT, Vec<u8>>,
    volatile: HashMap<PhysicalAddrT, Instant>,
}

impl PageCache {
    pub fn new() -> Self {
        Self {
            pages: LruCache::new(CACHE_CAP),
            volatile: HashMap::new(),
        }
    }

    pub async fn read<T: AsRawFd>(
        &mut self,
        dom: &Domain<T>,
        addr: PhysicalAddrT,
        sz: usize,
    ) -> Result<Vec<u8>> {
        if sz == 0 {
            return Ok(vec![]);
        }

        let key = addr & PADDR_KEY;
        let offset = (addr & PADDR_OFFSET) as usize;

        let pages_num = (offset + sz - 1) / PHYSICAL_PAGE_SZ as usize;
        match pages_num {
            0 => self.read_within_line(dom, addr, sz).await,
            _ => {
                let mut res = self
                    .read_within_line(dom, addr, PHYSICAL_PAGE_SZ as usize - offset)
                    .await?;
                for i in 1..pages_num as u64 {
                    let mut v = self
                        .read_within_line(
                            dom,
                            key + i * PHYSICAL_PAGE_SZ,
                            PHYSICAL_PAGE_SZ as usize,
                        )
                        .await?;
                    res.append(&mut v)
                }

                let remaining = offset + sz - pages_num * PHYSICAL_PAGE_SZ as usize;
                let mut v = self
                    .read_within_line(dom, key + pages_num as u64 * PHYSICAL_PAGE_SZ, remaining)
                    .await?;
                res.append(&mut v);
                Ok(res)
            }
        }
    }

    async fn read_within_line<T: AsRawFd>(
        &mut self,
        dom: &Domain<T>,
        addr: PhysicalAddrT,
        sz: usize,
    ) -> Result<Vec<u8>> {
        let key = addr & PADDR_KEY;
        let offset = (addr & PADDR_OFFSET) as usize;

        match self.pages.get(&key) {
            Some(vec) => Ok(vec[offset..offset + sz].to_vec()),
            None => {
                match self.volatile.get(&key) {
                    Some(inst) if Instant::now().duration_since(*inst) >= VOLATILE_TIMEOUT => {
                        self.volatile.remove(&key);
                    }
                    Some(_) => {
                        return Ok(dom
                            .send(ReadPhysical::new(key | offset as u64, sz as u64))
                            .await?);
                    }
                    None => (),
                }

                let mut msg = SetPageAccess::new();
                let mut builder = PageAccessEntryBuilder::new(key);
                builder.set_read().set_execute();
                msg.push(builder.build());
                dom.send(msg).await?;

                let page = dom.send(ReadPhysical::new(key, PHYSICAL_PAGE_SZ)).await?;
                let ret = page[offset..offset + sz].to_vec();
                self.pages.put(key, page);

                Ok(ret)
            }
        }
    }

    pub async fn remove<T: AsRawFd>(&mut self, dom: &Domain<T>, addr: PhysicalAddrT) -> Result<()> {
        let key = addr & PADDR_KEY;
        if self.pages.pop(&key).is_some() {
            let mut msg = SetPageAccess::new();
            let mut builder = PageAccessEntryBuilder::new(key);
            builder.set_read().set_write().set_execute();
            msg.push(builder.build());
            dom.send(msg).await?;
        }
        self.volatile.insert(key, Instant::now());
        Ok(())
    }

    pub async fn flush<T>(&mut self, _dom: &Domain<T>) -> Result<()> {
        self.pages.clear();
        self.volatile.clear();
        Ok(())
    }
}
