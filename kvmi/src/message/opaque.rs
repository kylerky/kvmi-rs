use super::{Messenger, ReqHandle};
use crate::*;
pub trait Msg: Messenger {
    fn get_req_info(&mut self) -> (Option<ReqHandle>, Vec<Vec<u8>>);
    fn get_error(&self) -> Error;
    fn construct_reply(&self, result: Vec<u8>) -> Self::Reply;
}

#[derive(Debug)]
pub struct Request {
    pub size: usize,
    pub kind: u16,
    pub seq: u32,
    pub result: sync::Sender<Vec<u8>>,
}
