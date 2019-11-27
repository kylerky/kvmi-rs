use async_std::os::unix::net::UnixListener;
use async_std::prelude::*;
use async_std::task;

use std::env::{self, Args};
use std::fs;
use std::fs::Permissions;
use std::io;
use std::os::unix::fs::PermissionsExt;

use kvmi_semantic::{Domain, RekallProfile};

use kvmi::HSToWire;

fn main() -> Result<(), io::Error> {
    env_logger::init();

    let args = env::args();
    let path = parse_args(args)?;

    task::block_on(listen(&path))
}

fn parse_args(mut args: Args) -> Result<String, io::Error> {
    let path = args.nth(1);
    if let Some(path) = path {
        if args.next().is_none() {
            return Ok(path);
        }
    }
    Err(io::Error::from(io::ErrorKind::InvalidInput))
}

async fn listen(path: &str) -> Result<(), io::Error> {
    let listener = UnixListener::bind(path).await?;
    println!("Listening for connections");

    fs::set_permissions(path, Permissions::from_mode(0o666))?;
    if let Some(stream) = listener.incoming().next().await {
        println!("Accepted a new connection");
        let stream = stream?;

        let rekall_profile = r#"
            {
                "$CONSTANTS": {
                   "PsActiveProcessHead": 4405536, 
                   "PsInitialSystemProcess": 5698464
                },
                "$FUNCTIONS": {
                    "KiSystemCall32Shadow": 3468800, 
                    "KiSystemCall64Shadow": 3469632 
                },
                "$STRUCTS": {
                    "_EPROCESS": [2176, {
                        "ActiveProcessLinks": [752, ["_LIST_ENTRY", {}]],
                        "UniqueProcessId": [744, ["Pointer", {
                         "target": "Void"
                        }]],
                        "ImageFileName": [1104, ["Array", {
                         "count": 15, 
                         "target": "unsigned char"
                        }]]
                    }],
                    "_KPROCESS": [736, {
                        "DirectoryTableBase": [40, ["unsigned long long", {}]]
                    }],
                    "_LIST_ENTRY": [16, {
                        "Blink": [8, ["Pointer", {
                            "target": "_LIST_ENTRY"
                        }]], 
                        "Flink": [0, ["Pointer", {
                            "target": "_LIST_ENTRY"
                        }]]
                    }],
                    "_KUSER_SHARED_DATA": [1808, {
                        "NtMajorVersion": [620, ["unsigned long", {}]], 
                        "NtMinorVersion": [624, ["unsigned long", {}]]
                    }]
                }
            }
        "#;

        let rekall_profile: RekallProfile = serde_json::from_str(&rekall_profile)?;
        let _dom = Domain::new(stream, |_, _, _| Some(HSToWire::new()), &rekall_profile).await?;
    }

    Ok(())
}
