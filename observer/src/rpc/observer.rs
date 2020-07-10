use std::io;
use std::net::SocketAddr;

use futures::select;
use futures::AsyncReadExt;
use futures::FutureExt;

use async_std::sync::Sender;

use crate::kvmi_capnp::event::detail::{File, Fork, Tcp};
use crate::kvmi_capnp::{FileAccess, TcpAccess};
use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::twoparty::{VatId, VatNetwork};
use capnp_rpc::RpcSystem;

use crate::kvmi_capnp::{consumer, event, publisher, subscription};

use crate::graph::{self, *};

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

pub struct Consumer {
    ch: Sender<(Entity, Event, Entity)>,
}
impl consumer::Server<event::Owned> for Consumer {
    fn push(
        &mut self,
        params: consumer::PushParams<event::Owned>,
        _res: consumer::PushResults<event::Owned>,
    ) -> Promise<(), capnp::Error> {
        let tx = self.ch.clone();
        Promise::from_future(async move {
            let event = params.get()?.get_event()?;
            let detail = event.get_detail();

            let subject = Entity::Process(Process {
                name: String::from(event.get_proc_file()?),
                pid: event.get_pid(),
                ppid: event.get_ppid(),
            });
            match detail.which()? {
                File(file) => {
                    use FileAccess::*;
                    let file = file?;
                    let access = match file.get_access()? {
                        Read => EventType::Read,
                        Write => EventType::Write,
                        Exec => EventType::Exec,
                        Open => EventType::Open,
                        Remove => EventType::Remove,
                    };
                    let graph_event = Event {
                        access,
                        timestamp: event.get_time_stamp(),
                    };
                    let object = Entity::File(graph::File {
                        name: String::from(file.get_name()?),
                    });
                    tx.send((subject, graph_event, object)).await;
                }
                Fork(_) => (),
                Tcp(tcp) => {
                    let tcp = tcp?;
                    let access = match tcp.get_access()? {
                        TcpAccess::Send => EventType::Write,
                        TcpAccess::Recv => EventType::Read,
                        _ => EventType::Open,
                    };
                    let event_graph = Event {
                        access,
                        timestamp: event.get_time_stamp(),
                    };
                    let object = Entity::NetworkEndpoint(graph::NetworkEndpoint {
                        addr: String::from(tcp.get_address()?),
                    });
                    tx.send((subject, event_graph, object)).await;
                }
            }
            Ok(())
        })
    }
}

pub async fn subscribe(
    addr: &SocketAddr,
    ch: Sender<(Entity, Event, Entity)>,
) -> Result<(), io::Error> {
    let (rpc_system, client) = connect(addr)?;

    let consumer: consumer::Client<_> = capnp_rpc::new_client(Consumer { ch });

    let mut rpc_system = rpc_system.fuse();
    let mut subscribe = Box::pin(client.subscribe(consumer)).fuse();

    let mut _subscription = None;
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
