#[derive(Debug)]
pub enum Entity {
    Process(Process),
    File(File),
    NetworkEndpoint(NetworkEndpoint),
}

#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
}

#[derive(Debug)]
pub struct File {
    pub name: String,
}

#[derive(Debug)]
pub struct NetworkEndpoint {
    pub addr: String,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Read,
    Write,
    Exec,
    Fork,
    Open,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub access: EventType,
    pub timestamp: u64,
}
