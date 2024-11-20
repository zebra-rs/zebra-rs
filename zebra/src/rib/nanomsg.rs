use std::io::Read;

use nanomsg::{Protocol, Socket};
use serde::{Deserialize, Serialize};
use serde_json::Value;

struct Nanomsg {
    socket: Socket,
}

#[derive(Debug, Serialize, Deserialize)]
struct Mesg {
    method: String,
    data: Value,
}

impl Nanomsg {
    pub fn new() -> anyhow::Result<Self> {
        let mut socket = Socket::new(Protocol::Pair)?;
        socket.bind("ipc:///tmp/ipc/pair/fibd_isisd")?;
        let nanomsg = Self { socket };
        Ok(nanomsg)
    }

    pub async fn event_loop(&mut self) {
        println!("Here we are");
        let mut text = String::new();
        loop {
            match self.socket.read_to_string(&mut text) {
                Ok(_) => {
                    println!("{}", text);
                    text.pop();
                    let value: Result<Mesg, serde_json::Error> = serde_json::from_str(&text);
                    match value {
                        Ok(msg) => {
                            println!("method {:?}", msg.method);
                            if msg.method == "vrf:request" {
                                println!("VRF REquest");
                                //
                            }
                        }
                        Err(err) => {
                            println!("err {}", err);
                            // break;
                        }
                    }
                }
                Err(err) => {
                    break;
                }
            }
            text.clear();
        }
    }
}

pub fn serve() {
    let mut nanomsg = Nanomsg::new();
    if let Ok(mut nanomsg) = nanomsg {
        tokio::spawn(async move {
            nanomsg.event_loop().await;
        });
    }
}
