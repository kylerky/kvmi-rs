use std::io;
use std::mem;
use std::net::SocketAddr;

use futures::select;
use futures::stream::FuturesUnordered;
use futures::{AsyncReadExt, FutureExt, StreamExt};

use capnp::capability::{Promise, Response};
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::twoparty::{VatId, VatNetwork};
use capnp_rpc::{Disconnector, RpcSystem};

use crate::kvmi_capnp::{consumer, event, publisher, subscription};

use async_std::net::TcpListener;
use async_std::sync::{self, Receiver, Sender};
use async_std::task;

use log::{error, info};

use crate::collect::LogChT;

struct Subscription {
    _tx: Sender<()>,
}
impl subscription::Server for Subscription {}
impl Subscription {
    fn new(_tx: Sender<()>) -> Self {
        Self { _tx }
    }
}

type PushRespT = Response<consumer::push_results::Owned<event::Owned>>;
struct Consumer {
    consumer: consumer::Client<event::Owned>,
}
impl Consumer {
    fn new(consumer: consumer::Client<event::Owned>) -> Self {
        Self { consumer }
    }

    pub fn push_promise(&self, event: event::Reader) -> Promise<PushRespT, capnp::Error> {
        let mut req = self.consumer.push_request();
        if let Err(e) = req.get().set_event(event) {
            return Promise::err(e);
        }
        req.send().promise
    }
}

type ServerChanT = Consumer;
pub struct RpcServer {
    consumer_tx: Sender<ServerChanT>,
    close_tx: Sender<()>,
}
impl RpcServer {
    fn new() -> (Self, Receiver<ServerChanT>, Receiver<()>) {
        let (consumer_tx, consumer_rx) = sync::channel(1);
        let (close_tx, close_rx) = sync::channel(1);
        (
            Self {
                consumer_tx,
                close_tx,
            },
            consumer_rx,
            close_rx,
        )
    }
}
impl publisher::Server<event::Owned> for RpcServer {
    fn subscribe(
        &mut self,
        params: publisher::SubscribeParams<event::Owned>,
        mut res: publisher::SubscribeResults<event::Owned>,
    ) -> Promise<(), capnp::Error> {
        let consumer_tx = self.consumer_tx.clone();
        let close_tx = self.close_tx.clone();
        Promise::from_future(async move {
            let consumer = params.get()?.get_consumer()?;
            let consumer = Consumer::new(consumer);
            consumer_tx.send(consumer).await;

            let (sub_tx, sub_rx) = sync::channel(1);
            // notify that a subscription is dropped
            task::spawn(async move {
                sub_rx.recv().await.ok();
                close_tx.send(()).await;
            });

            let subscription = Subscription::new(sub_tx);
            let subscription = capnp_rpc::new_client(subscription);
            res.get().set_subscription(subscription);
            Ok(())
        })
    }
}

pub async fn listen(addr: &SocketAddr, event_log_rx: Receiver<LogChT>) -> Result<(), io::Error> {
    let listener = TcpListener::bind(addr).await?;

    let (rpc_server, consumer_rx, close_rx) = RpcServer::new();
    let observer: publisher::Client<_> = capnp_rpc::new_client(rpc_server);

    // start draining the event channel
    let (mut drain_tx, drain_rx) = sync::channel(500);
    let mut drain_handle = task::spawn(drain(event_log_rx.clone(), drain_rx));

    while let Some(stream) = listener.incoming().next().await {
        // stop draining the event channel
        mem::drop(drain_tx);
        drain_handle.await;

        let stream = stream?;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.split();

        let network = VatNetwork::new(reader, writer, Side::Server, Default::default());
        let rpc_system = RpcSystem::new(Box::new(network), Some(observer.clone().client));

        if let Err(e) = streaming(
            rpc_system,
            consumer_rx.clone(),
            close_rx.clone(),
            event_log_rx.clone(),
        )
        .await
        {
            info!("Connection closed: {}", e);
        }

        // start draining the event channel
        let (tx, drain_rx) = sync::channel(500);
        drain_tx = tx;
        drain_handle = task::spawn(drain(event_log_rx.clone(), drain_rx));
    }

    Ok(())
}

async fn drain(event_log_rx: Receiver<LogChT>, sd_rx: Receiver<()>) {
    let mut log_rx = event_log_rx.fuse();
    let mut sd_rx = sd_rx.fuse();
    loop {
        select! {
            _ = log_rx.next() => (),
            _ = sd_rx.next() => return (),
        }
    }
}

struct RpcCleanUp(Option<Disconnector<VatId>>);
impl Drop for RpcCleanUp {
    fn drop(&mut self) {
        if let Err(e) = task::block_on(self.0.take().unwrap()) {
            error!("Error cleaning up the RPC system: {}", e);
        }
    }
}

async fn streaming(
    rpc_system: RpcSystem<VatId>,
    consumer_rx: Receiver<ServerChanT>,
    close_rx: Receiver<()>,
    event_rx: Receiver<LogChT>,
) -> Result<(), io::Error> {
    // clean up the RPC system on exit
    let _clean_up = RpcCleanUp(Some(rpc_system.get_disconnector()));

    let mut consumer_rx = consumer_rx.fuse();
    let mut close_rx = close_rx.fuse();
    let mut rpc_system = rpc_system.fuse();
    let mut event_rx = event_rx.fuse();
    let mut push_fut = FuturesUnordered::new();

    let mut consumer = None;
    #[allow(clippy::unnecessary_mut_passed)]
    loop {
        select! {
            rpc_res = rpc_system => {
                let e = match rpc_res {
                    Ok(()) => io::Error::new(io::ErrorKind::BrokenPipe, "RPC system is down"),
                    Err(err) => io::Error::new(io::ErrorKind::BrokenPipe, err),
                };
                return Err(e);
            },
            cons = consumer_rx.next() => {
                consumer = cons;
            },
            _ = close_rx.next() => {
                // event stream unsubscribed
                // clear the consumer and pending pushes
                consumer = None;
                push_fut = FuturesUnordered::new();
            },
            event_log = event_rx.next() => {
                if let Some(consumer) = consumer.as_ref() {
                    if let Some(event_log) = event_log {
                        push_fut.push(consumer.push_promise(
                            event_log
                                .into_reader()
                                .get_root::<event::Reader>()
                                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                            )
                        );
                    }
                }
            },
            push_res = push_fut.select_next_some() => {
                if let Err(e) = push_res {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
                }
            },
        }
    }
}
