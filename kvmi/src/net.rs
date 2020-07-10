use crate::Result;

use std::io::{self, ErrorKind};
use std::net::Shutdown;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_std::io::prelude::*;
use async_std::sync::Arc;

use smol::Async;

use nix::errno::Errno;
use nix::sys::socket::{self, ControlMessage, MsgFlags, SockAddr};
use nix::sys::uio::IoVec;

#[derive(Debug)]
pub struct Stream<T>(Arc<Async<T>>);

impl<T: AsRawFd> Stream<T> {
    pub fn new(s: Async<T>) -> Self {
        Stream(Arc::new(s))
    }

    pub async fn sendmsg(
        &self,
        vec: Vec<Vec<u8>>,
        cmsgs: &[ControlMessage<'_>],
        flags: MsgFlags,
        addr: Option<&SockAddr>,
    ) -> Result<usize> {
        self.0
            .write_with(move |s| {
                let fd = s.as_raw_fd();
                let iov: Vec<IoVec<&[u8]>> =
                    vec.iter().map(|i| IoVec::from_slice(&i[..])).collect();
                socket::sendmsg(fd, &iov, cmsgs, flags, addr).map_err(|e| match e {
                    nix::Error::Sys(Errno::EAGAIN) => io::Error::from(ErrorKind::WouldBlock),
                    nix::Error::Sys(errno) => errno.into(),
                    nix::Error::InvalidPath => {
                        io::Error::new(ErrorKind::InvalidInput, "Invalid path")
                    }
                    nix::Error::InvalidUtf8 => {
                        io::Error::new(ErrorKind::InvalidInput, "Invalid UTF-8")
                    }
                    nix::Error::UnsupportedOperation => {
                        io::Error::new(ErrorKind::InvalidInput, "The operation is not supported")
                    }
                })
            })
            .await
            .map_err(|e| e.into())
    }
}

impl Stream<UnixStream> {
    pub fn shutdown(&self, side: Shutdown) -> Result<()> {
        self.0.get_ref().shutdown(side).map_err(|e| e.into())
    }
}

impl<T> Clone for Stream<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T: AsRawFd> From<Async<T>> for Stream<T> {
    fn from(s: Async<T>) -> Self {
        Stream::new(s)
    }
}

impl<T> Read for &Stream<T>
where
    for<'a> &'a T: io::Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self.0).poll_read(cx, buf)
    }
}

impl<T> Read for Stream<T>
where
    for<'a> &'a T: io::Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self).poll_read(cx, buf)
    }
}
