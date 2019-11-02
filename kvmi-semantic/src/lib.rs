#[cfg(test)]
mod tests;

use async_std::io::prelude::*;
use async_std::os::unix::io::AsRawFd;

use futures::channel::mpsc as mpsc_fut;

use kvmi::message::GetRegistersReply;
use kvmi::{DomainBuilder, Event, HSToWire};

pub struct Domain {
    dom: kvmi::Domain,
    event_rx: mpsc_fut::Receiver<Event>,
}

#[derive(Debug, PartialEq)]
enum PageMode {
    Real,
    IA32e,
    Other,
}

impl Domain {
    pub async fn new<T, F>(stream: T, validator: F) -> kvmi::Result<Self>
    where
        T: Write + Read + Send + AsRawFd + Unpin + 'static,
        F: FnOnce(&str, &[u8], i64) -> Option<HSToWire>,
    {
        let dom = DomainBuilder::new(stream);
        let (dom, event_rx) = dom.handshake(validator).await?;
        Ok(Self { dom, event_rx })
    }

    fn get_paging_mode_from(reply: GetRegistersReply) -> PageMode {
        use PageMode::*;

        let regs = reply.get_regs();
        let cr0 = regs.sregs.cr0;

        if cr0 & (1 << 31) == 0 {
            return Real;
        }

        let cr4 = regs.sregs.cr4;
        let pae = cr4 & (1 << 5);

        let efer = regs.sregs.efer;
        let lme = efer & (1 << 8);

        if pae != 0 && lme != 0 {
            return IA32e;
        }

        Other
    }
}
