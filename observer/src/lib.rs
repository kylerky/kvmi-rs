#![recursion_limit = "256"]

#[allow(dead_code, clippy::redundant_field_names, clippy::match_single_binding)]
mod kvmi_capnp {
    include!(concat!(env!("OUT_DIR"), "/kvmi_capnp.rs"));
}

pub mod collect;
pub mod graph;
pub mod rpc;
pub mod web;
