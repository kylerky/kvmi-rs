// use std::path::PathBuf;
use std::io::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::{fs, process};

use structopt::StructOpt;

use async_std::sync::{self, Arc};
use async_std::task;

use observer::collect;
use observer::rpc;

use signal_hook::flag;

use kvmi_semantic::RekallProfile;

#[derive(StructOpt)]
#[structopt(name = "observer")]
struct Opt {
    listen_addr: SocketAddr,

    #[structopt(short, long)]
    kvmi: PathBuf,

    #[structopt(short, long)]
    profile: PathBuf,
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

    let exit = Arc::new(AtomicBool::new(false));
    flag::register(signal_hook::SIGINT, Arc::clone(&exit))?;

    let profile = fs::read_to_string(opt.profile.as_path())?;
    let profile: RekallProfile = serde_json::from_str(&profile[..])?;

    let (tx, rx) = sync::channel(30);
    task::spawn(collect::listen(opt.kvmi, profile, exit, tx));
    task::block_on(rpc::listen(&opt.listen_addr, rx))?;
    Ok(())
}
