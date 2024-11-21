use std::io::Read;

use nanomsg::{Protocol, Socket};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, to_string, Value};

struct Nanomsg {
    socket: Socket,
}

#[derive(Debug, Serialize, Deserialize)]
struct Msg {
    method: String,
    data: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouterIdRequest {
    #[serde(rename = "vrf-id")]
    vrf_id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct MsgSend {
    method: String,
    data: MsgEnum,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum MsgEnum {
    Interface(InterfaceMsg),
}

#[derive(Debug, Serialize, Deserialize)]
struct VrfMsg {
    #[serde(rename = "vrf-id")]
    vrf_id: u32,
    #[serde(rename = "vrf-name")]
    vrf_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InterfaceMsg {
    iftype: u32,
    ifname: String,
    ifindex: u32,
    #[serde(rename = "mib-ifindex")]
    mib_ifindex: u32,
    flags: u32,
    mtu: u32,
    vrf: VrfMsg,
    #[serde(rename = "if-hw-addr-len")]
    if_hw_addr_len: u32,
    #[serde(rename = "if-hw-addr")]
    if_hw_addr: String,
}

use std::io::Write;

impl Nanomsg {
    pub fn new() -> anyhow::Result<Self> {
        let mut socket = Socket::new(Protocol::Pair)?;
        socket.bind("ipc:///tmp/ipc/pair/fibd_isisd")?;
        let nanomsg = Self { socket };
        Ok(nanomsg)
    }

    pub fn parse(&mut self, text: &String) -> anyhow::Result<()> {
        let value: Result<Msg, serde_json::Error> = serde_json::from_str(&text);
        match value {
            Ok(msg) => {
                println!("method {:?}", msg.method);
                if msg.method == "router-id:request" {
                    let data: Result<RouterIdRequest, _> = from_value(msg.data);
                    println!("{:?}", data);
                    let intf_msg = InterfaceMsg {
                        iftype: 0,
                        ifname: String::from("lo"),
                        ifindex: 1,
                        mib_ifindex: 1,
                        flags: 73,
                        mtu: 65536,
                        vrf: VrfMsg {
                            vrf_id: 0,
                            vrf_name: "Global Table".into(),
                        },
                        if_hw_addr_len: 6,
                        if_hw_addr: "0000.0000.0000".into(),
                    };
                    let msg = MsgSend {
                        method: String::from("interface:add"),
                        data: MsgEnum::Interface(intf_msg),
                    };
                    self.socket.write(to_string(&msg)?.as_bytes());
                }
            }
            Err(err) => {
                println!("err {}", err);
                // break;
            }
        }
        Ok(())
    }

    pub async fn event_loop(&mut self) {
        println!("Here we are");
        let mut text = String::new();
        loop {
            match self.socket.read_to_string(&mut text) {
                Ok(_) => {
                    println!("{}", text);
                    text.pop();
                    self.parse(&text);
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
