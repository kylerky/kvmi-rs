use std::io::Error;
use std::net::SocketAddr;
use std::process;

use structopt::StructOpt;

use async_std::sync;
use async_std::task;

use observer::{graph, rpc};

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

    let (tx, rx) = sync::channel(100);
    let constructor = task::spawn(graph::construct(rx));
    task::block_on(rpc::subscribe(&opt.addr, tx))?;
    task::block_on(async { constructor.await });
    Ok(())
}
