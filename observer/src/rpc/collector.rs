use std::io;
use std::net::SocketAddr;

use futures::select;
use futures::stream::FuturesUnordered;
use futures::{AsyncReadExt, FutureExt, StreamExt};

use capnp::capability::{Promise, Response};
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::twoparty::{VatId, VatNetwork};
use capnp_rpc::RpcSystem;

use crate::kvmi_capnp::{consumer, event, publisher, subscription, Access};

use async_std::net::TcpListener;
use async_std::sync::{self, Receiver, Sender};
use async_std::task;

use log::error;

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

    pub fn push_promise(&self, i: u64) -> Promise<PushRespT, capnp::Error> {
        let mut req = self.consumer.push_request();
        let mut event = req.get().init_event();
        event.set_pid(i);
        event.set_proc_name("test");

        let mut file = event.init_detail().init_file();
        file.set_name("fname");
        file.set_access(Access::Read);
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
                sub_rx.recv().await;
                close_tx.send(()).await;
            });

            let subscription = Subscription::new(sub_tx);
            let subscription =
                subscription::ToClient::new(subscription).into_client::<capnp_rpc::Server>();
            res.get().set_subscription(subscription);
            Ok(())
        })
    }
}

pub async fn listen(addr: &SocketAddr) -> Result<(), io::Error> {
    let listener = TcpListener::bind(addr).await?;

    let (rpc_server, consumer_rx, close_rx) = RpcServer::new();
    let observer = publisher::ToClient::new(rpc_server).into_client::<capnp_rpc::Server>();

    let (tx, rx) = sync::channel(1);
    task::spawn(async move {
        use std::time::Duration;
        let mut interval = async_std::stream::interval(Duration::from_secs(1));
        let mut i = 0;
        while let Some(_) = interval.next().await {
            tx.send(i).await;
            i += 1;
        }
    });
    while let Some(stream) = listener.incoming().next().await {
        let stream = stream?;
        stream.set_nodelay(true)?;
        let (reader, writer) = stream.split();

        let network = VatNetwork::new(reader, writer, Side::Server, Default::default());
        let rpc_system = RpcSystem::new(Box::new(network), Some(observer.clone().client));
        // if let Err(e) = task::block_on(rpc_system) {
        //     error!("rpc system error: {}", e);
        // }
        if let Err(e) = task::block_on(streaming(
            rpc_system,
            consumer_rx.clone(),
            close_rx.clone(),
            rx.clone(),
        )) {
            error!("rpc system error: {}", e);
        }
    }

    Ok(())
}

async fn streaming(
    rpc_system: RpcSystem<VatId>,
    consumer_rx: Receiver<ServerChanT>,
    close_rx: Receiver<()>,
    event_rx: Receiver<u64>,
) -> Result<(), io::Error> {
    let mut consumer_rx = consumer_rx.fuse();
    let mut close_rx = close_rx.fuse();
    let mut rpc_system = rpc_system.fuse();
    let mut event_rx = event_rx.fuse();
    let mut push_fut = FuturesUnordered::new();

    let mut consumer = None;
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
            event = event_rx.next() => {
                if let Some(consumer) = consumer.as_ref() {
                    if let Some(i) = event {
                        push_fut.push(consumer.push_promise(i));
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
