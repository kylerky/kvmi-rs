use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

use structopt::StructOpt;

use async_std::{sync, task};

use futures::select;
use futures::FutureExt;

use observer::web::consume;
use observer::{graph, rpc};

use regex::RegexSet;

#[derive(StructOpt)]
struct Opt {
    addr: SocketAddr,

    #[structopt(short, long)]
    log_dir: Option<PathBuf>,
}

fn main() {
    let code = match run() {
        Ok(()) => exitcode::OK,
        Err(_) => exitcode::IOERR,
    };
    process::exit(code);
}

fn run() -> Result<(), Error> {
    let opt = Opt::from_args();

    if let Some(path) = &opt.log_dir {
        if !path.is_dir() {
            eprintln!("Expect a directory for logging graphs");
            return Err(Error::from(ErrorKind::InvalidInput));
        }
    }

    env_logger::init();

    let (log_tx, log_rx) = sync::channel(1000);
    let (graph_tx, graph_rx) = sync::channel(10);
    let (_stream_tx, stream_rx) = sync::channel(10);

    let secrets_pat = [r".*\.secret$", r".*\.kvmi$"];
    let secrets = RegexSet::new(&secrets_pat).unwrap();
    let constructor = task::spawn(graph::construct(log_rx, graph_tx, secrets));

    let consumer = task::spawn(consume::consume(graph_rx, opt.log_dir.clone(), stream_rx));

    task::block_on(async {
        let mut subscribe = Box::pin(rpc::subscribe(&opt.addr, log_tx)).fuse();
        let mut consumer = consumer.fuse();
        loop {
            select! {
                res = consumer => {
                    if let Err(e) = res {
                        break Err(e);
                    }
                }
                res = subscribe => {
                    if let Err(e) = res {
                        break Err(e);
                    }
                }
                complete => break Ok(()),
            }
        }
    })?;
    task::block_on(async { constructor.await });
    Ok(())
}
