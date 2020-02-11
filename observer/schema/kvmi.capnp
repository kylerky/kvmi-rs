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
    procName @1 :Text;

    detail :union {
        file @2 :FileEvent;
        fork @3 :ForkEvent;
        tcp @4 :TcpEvent;
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
