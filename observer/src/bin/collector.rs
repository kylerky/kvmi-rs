// use std::path::PathBuf;
use std::io::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::{fs, process};

use structopt::StructOpt;

use async_std::sync;
use async_std::task;

use observer::collect;
use observer::rpc;

use signal_hook::iterator::Signals;

use kvmi_semantic::RekallProfile;

use futures::select;
use futures::{FutureExt, StreamExt};

use log::error;

#[derive(StructOpt)]
#[structopt(name = "observer")]
struct Opt {
    listen_addr: SocketAddr,

    #[structopt(short, long)]
    kvmi: PathBuf,

    #[structopt(short, long)]
    profile: PathBuf,
}
impl Opt {
    fn get_paths(self) -> (SocketAddr, PathBuf, PathBuf) {
        (self.listen_addr, self.kvmi, self.profile)
    }
}

fn main() {
    let code = match run() {
        Ok(()) => exitcode::OK,
        Err(e) => {
            error!("{}", e);
            exitcode::IOERR
        }
    };
    process::exit(code);
}

fn run() -> Result<(), Error> {
    let opt = Opt::from_args();

    let profile = fs::read_to_string(opt.profile.as_path())?;
    let profile: RekallProfile = serde_json::from_str(&profile[..])?;

    let (rpc_sd_tx, rpc_sd_rx) = sync::channel::<()>(1);
    let (collect_sd_tx, collect_sd_rx) = sync::channel::<()>(1);
    let (sig_tx, sig_rx) = sync::channel::<()>(1);

    let signals = Signals::new(&[signal_hook::SIGINT, signal_hook::SIGTERM])?;
    let signals2 = signals.clone();
    let sig_handle = task::spawn_blocking(move || {
        // move sig_tx inside
        let _tx = sig_tx;
        // wait for the next SIGINT or SIGTERM signal
        signals2.into_iter().next();
        // dropping tx should yield a shutdown
    });

    let (rpc_addr, kvmi, _) = opt.get_paths();
    let (log_tx, log_rx) = sync::channel(30);
    let sig_rx2 = sig_rx.clone();
    let collect_handle = task::spawn(async move {
        // keep the sender to prevent rpc from shutting down
        let _tx = collect_sd_tx;

        let mut sig = sig_rx2.fuse();
        let mut rpc = rpc_sd_rx.fuse();
        select! {
            res = collect::listen(kvmi, profile, log_tx).fuse() => res,
            _ = sig.next() => Ok(()),
            _ = rpc.next() => Ok(()),
        }
    });

    let ret = task::block_on(async move {
        // keep the sender to prevent collect from shutting down
        let _tx = rpc_sd_tx;

        let mut sig = sig_rx.fuse();
        let mut collect = collect_sd_rx.fuse();
        select! {
            res = rpc::listen(&rpc_addr, log_rx).fuse() => res,
            _ = sig.next() => Ok(()),
            _ = collect.next() => Ok(()),
        }
    });

    ret.and(task::block_on(async move {
        signals.close();
        sig_handle.await;

        collect_handle.await
    }))
}
