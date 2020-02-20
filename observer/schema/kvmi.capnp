@0x9f506f50f5e57037;

interface Publisher(T) {
    subscribe @0 (consumer: Consumer(T)) -> (subscription: Subscription);
}

interface Subscription {}

interface Consumer(T) {
    push @0 (event: T);
}

struct Event {
    pid @0 :UInt64;
    ppid @1 :UInt64;
    procFile @2 :Text;
    timeStamp @3 :UInt64;

    detail :union {
        file @4 :FileEvent;
        fork @5 :ForkEvent;
        tcp @6 :TcpEvent;
    }
}

enum FileAccess {
    read @0;
    write @1;
    exec @2;
    open @3;
}

struct FileEvent {
    name @0 :Text;
    access @1 :FileAccess;
}

struct ForkEvent {
    pid @0 :UInt64;
    procName @1 :Text;
}

enum TcpAccess {
    recv @0;
    send @1;
    connect @2;
    accept @3;
}

struct TcpEvent {
    address @0 :Text;
    access @1 :TcpAccess;
}
