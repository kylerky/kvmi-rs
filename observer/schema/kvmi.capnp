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
    }
}

enum Access {
    read @0;
    write @1;
    exec @2;
}

struct FileEvent {
    name @0 :Text;
    access @1 :Access;
}

struct ForkEvent {
    pid @0 :UInt64;
}
