mod log;

use async_std::net::TcpStream;
use async_std::sync::{Arc, Receiver};
use async_std::task;

use std::io::Error;
use std::path::PathBuf;
use std::sync::atomic::AtomicU16;

use futures::select;
use futures::stream::{FuturesUnordered, StreamExt};

use crate::graph::ProvGraph;

pub async fn consume(
    graphs: Receiver<ProvGraph>,
    path: Option<PathBuf>,
    streams: Receiver<TcpStream>,
) -> Result<(), Error> {
    let counter = Arc::new(AtomicU16::new(0));

    let mut _stream = None;
    let mut streams = streams.fuse();
    let mut graphs = graphs.fuse();
    let mut consume_graphs = FuturesUnordered::new();
    let mut res = loop {
        select! {
            new_stream = streams.next() => {
                match new_stream {
                    None => break Ok(()),
                    Some(new_stream) => _stream = Some(new_stream),
                }
            },
            graph = graphs.next() => {
                match graph {
                    None => break Ok(()),
                    Some(graph) => {
                        let handle = task::spawn(consume_graph(graph, path.clone(), Arc::clone(&counter)));
                        consume_graphs.push(handle);
                    }
                }
            }
            res = consume_graphs.select_next_some() => {
                if let Err(e) = res {
                    break Err(e);
                }
            }
        }
    };
    while !consume_graphs.is_empty() {
        let r = consume_graphs.select_next_some().await;
        res = res.and(r);
    }
    res
}

async fn consume_graph(
    graph: ProvGraph,
    path: Option<PathBuf>,
    counter: Arc<AtomicU16>,
) -> Result<(), Error> {
    if let Some(dir) = path {
        log::write_file(&graph, dir.clone(), counter).await?;
    }
    Ok(())
}
