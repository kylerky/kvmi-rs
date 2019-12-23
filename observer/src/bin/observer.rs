use std::io::Error;
use std::net::SocketAddr;
use std::process;

use structopt::StructOpt;


use async_std::task;

use observer::rpc;

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
    task::block_on(rpc::subscribe(&opt.addr))?;
    Ok(())
}
