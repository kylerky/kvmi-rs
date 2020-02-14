use crate::PTR_SZ;
use crate::{IA32eAddrT, IA32eVirtual, Result};

use async_std::pin::Pin;
use async_std::stream::Stream;
use async_std::task::{Context, Poll};

use std::convert::TryInto;
use std::future::Future;

use futures::future::BoxFuture;

pub struct ForwardIter<'a> {
    v_space: &'a IA32eVirtual,
    flink_rva: IA32eAddrT,
    inner: BoxFuture<'a, Result<Vec<u8>>>,
}

impl<'a> ForwardIter<'a> {
    pub fn new(v_space: &'a IA32eVirtual, list_head: IA32eAddrT, flink_rva: IA32eAddrT) -> Self {
        let inner = Box::pin(v_space.read(list_head + flink_rva, PTR_SZ));
        Self {
            v_space,
            flink_rva,
            inner,
        }
    }
}

impl<'a> Stream for ForwardIter<'a> {
    type Item = IA32eAddrT;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        use Poll::*;
        match Pin::new(&mut self.inner).poll(cx) {
            Pending => Pending,
            Ready(Ok(curr)) => {
                let curr = u64::from_ne_bytes(curr[..].try_into().unwrap());
                self.inner = Box::pin(self.v_space.read(curr + self.flink_rva, PTR_SZ));
                Ready(Some(curr))
            }
            Ready(Err(_)) => Ready(None),
        }
    }
}
