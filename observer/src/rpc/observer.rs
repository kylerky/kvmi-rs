use std::io;
use std::net::SocketAddr;

use futures::select;
use futures::AsyncReadExt;
use futures::FutureExt;

use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::twoparty::{VatId, VatNetwork};
use capnp_rpc::RpcSystem;

use crate::kvmi_capnp::{consumer, event, publisher, subscription};

pub struct RpcClient {
    client: publisher::Client<event::Owned>,
}

impl RpcClient {
    fn new(client: publisher::Client<event::Owned>) -> Self {
        Self { client }
    }

    pub async fn subscribe(
        &self,
        consumer: consumer::Client<event::Owned>,
    ) -> Result<subscription::Client, capnp::Error> {
        let mut req = self.client.subscribe_request();
        req.get().set_consumer(consumer);
        let response = req.send().promise.await?;
        let sub = response.get()?.get_subscription()?;
        Ok(sub)
    }
}

pub struct Consumer;
impl consumer::Server<event::Owned> for Consumer {
    fn push(
        &mut self,
        params: consumer::PushParams<event::Owned>,
        _res: consumer::PushResults<event::Owned>,
    ) -> Promise<(), capnp::Error> {
        Promise::from_future(async move {
            let event = params.get()?.get_event()?;
            println!(
                "event pushed: {}, {}",
                event.get_pid(),
                event.get_proc_name()?
            );
            Ok(())
        })
    }
}

pub async fn subscribe(addr: &SocketAddr) -> Result<(), io::Error> {
    let (rpc_system, client) = connect(addr)?;

    let consumer = consumer::ToClient::new(Consumer).into_client::<capnp_rpc::Server>();

    let mut rpc_system = rpc_system.fuse();
    let mut subscribe = Box::pin(client.subscribe(consumer)).fuse();

    let mut _subscription = None;
    loop {
        select! {
            rpc_res = rpc_system => {
                let e = match rpc_res {
                    Ok(()) => io::Error::new(io::ErrorKind::BrokenPipe, "RPC system is down"),
                    Err(err) => io::Error::new(io::ErrorKind::BrokenPipe, err),
                };
                return Err(e);
            },
            res = subscribe => {
                let sub = res.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
                _subscription = Some(sub);
            },
        }
    }
}

fn connect(addr: &SocketAddr) -> Result<(RpcSystem<VatId>, RpcClient), io::Error> {
    let stream = std::net::TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;

    Ok(get_client(stream))
}

fn get_client(stream: std::net::TcpStream) -> (RpcSystem<VatId>, RpcClient) {
    let stream = async_std::net::TcpStream::from(stream);
    let (reader, writer) = stream.split();

    let network = VatNetwork::new(reader, writer, Side::Client, Default::default());
    let mut rpc_system = RpcSystem::new(Box::new(network), None);
    let client = rpc_system.bootstrap(Side::Server);

    (rpc_system, RpcClient::new(client))
}
