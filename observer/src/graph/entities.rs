#[derive(Debug, Clone, PartialEq)]
pub enum Entity {
    Process(Process),
    File(File),
    NetworkEndpoint(NetworkEndpoint),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct File {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkEndpoint {
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq)]
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
