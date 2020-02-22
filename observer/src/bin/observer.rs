use std::io::Error;
use std::net::SocketAddr;
use std::process;

use structopt::StructOpt;

use async_std::sync;
use async_std::task;

use observer::{graph, rpc};

use regex::RegexSet;

#[derive(StructOpt)]
struct Opt {
    addr: SocketAddr,
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

    env_logger::init();

    let (log_tx, log_rx) = sync::channel(300);
    let (graph_tx, _graph_rx) = sync::channel(10);

    let secrets_pat = [r".*\.secret$", r".*\.kvmi$"];
    let secrets = RegexSet::new(&secrets_pat).unwrap();
    let constructor = task::spawn(graph::construct(log_rx, graph_tx, secrets));

    task::block_on(rpc::subscribe(&opt.addr, log_tx))?;
    task::block_on(async { constructor.await });
    Ok(())
}
