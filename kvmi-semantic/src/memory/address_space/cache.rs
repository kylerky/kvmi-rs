use super::{Domain, PhysicalAddrT};
use super::{PADDR_OFFSET, PHYSICAL_PAGE_SZ};

use kvmi::message::ReadPhysical;

use lru::LruCache;

use std::time::{Duration, Instant};

use crate::Result;

const CACHE_CAP: usize = 1 << 18;
const PADDR_KEY: PhysicalAddrT = !PADDR_OFFSET;

const STALE_TIMEOUT: Duration = Duration::from_millis(100);

pub struct StalePageCache {
    pages: LruCache<PhysicalAddrT, (Vec<u8>, Instant)>,
}

impl StalePageCache {
    pub fn new() -> Self {
        Self {
            pages: LruCache::new(CACHE_CAP),
        }
    }

    pub async fn read(&mut self, dom: &Domain, addr: PhysicalAddrT, sz: usize) -> Result<Vec<u8>> {
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

    async fn read_within_line(
        &mut self,
        dom: &Domain,
        addr: PhysicalAddrT,
        sz: usize,
    ) -> Result<Vec<u8>> {
        let key = addr & PADDR_KEY;
        let offset = (addr & PADDR_OFFSET) as usize;

        match self.pages.get(&key) {
            Some((vec, inst)) if Instant::now().duration_since(*inst) < STALE_TIMEOUT => {
                return Ok(vec[offset..offset + sz].to_vec());
            }
            _ => (),
        }

        let page = dom.send(ReadPhysical::new(key, PHYSICAL_PAGE_SZ)).await?;
        let ret = page[offset..offset + sz].to_vec();
        self.pages.put(key, (page, Instant::now()));

        Ok(ret)
    }

    pub async fn remove(&mut self, _dom: &Domain, addr: PhysicalAddrT) -> Result<()> {
        let key = addr & PADDR_KEY;
        self.pages.pop(&key);
        Ok(())
    }

    pub async fn flush(&mut self, _dom: &Domain) -> Result<()> {
        self.pages.clear();
        Ok(())
    }
}
