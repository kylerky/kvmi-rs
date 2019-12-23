// use std::path::PathBuf;
use std::io::Error;
use std::net::SocketAddr;
use std::process;

use structopt::StructOpt;

use async_std::task;

use observer::rpc;

#[derive(StructOpt)]
#[structopt(name = "observer")]
struct Opt {
    listen_addr: SocketAddr,
    // #[structopt(short, long)]
    // kvmi_addr: PathBuf,

    // #[structopt(short, long)]
    // ptb: Option<u64>,
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
    task::block_on(rpc::listen(&opt.listen_addr))?;
    Ok(())
}
