use crate::graph::ProvGraph;

use std::io::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::SystemTime;

use async_std::fs::File;
use async_std::prelude::*;
use async_std::sync::Arc;
use async_std::task;

use petgraph::dot::{Config, Dot};

pub(super) async fn write_file(
    graph: &ProvGraph,
    mut dir: PathBuf,
    counter: Arc<AtomicU16>,
) -> Result<(), Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let num = counter.fetch_add(1, Ordering::Relaxed);
    dir.push(format!("{:x?}-{:x?}", timestamp, num));

    let mut file = File::create(dir).await?;
    task::block_on(write!(
        file,
        "{}",
        Dot::with_config(graph, &[Config::EdgeNoLabel])
    ))?;
    Ok(())
}
