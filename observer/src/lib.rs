#![recursion_limit = "256"]

#[allow(dead_code)]
mod kvmi_capnp {
    include!(concat!(env!("OUT_DIR"), "/kvmi_capnp.rs"));
}

pub mod collect;
pub mod graph;
pub mod rpc;
pub mod web;
