use crate::*;
pub trait Msg {
    fn get_req_info(&mut self) -> (Option<(Request, oneshot::Receiver<Vec<u8>>)>, Vec<Vec<u8>>);
    fn construct_reply(&self, result: Vec<u8>) -> Option<Reply>;
}

#[derive(Debug)]
pub struct Request {
    pub size: usize,
    pub kind: u16,
    pub seq: u32,
    pub result: oneshot::Sender<Vec<u8>>,
}
