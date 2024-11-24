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
    IsisGlobal(IsisGlobal),
    IsisInstance(IsisInstance),
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

#[derive(Debug, Serialize, Deserialize)]
struct IsisGlobal {
    hostname: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IsisInstance {
    #[serde(rename = "instance-tag")]
    instance_tag: String,
}

use std::io::Write;

impl Nanomsg {
    pub fn new() -> anyhow::Result<Self> {
        let mut socket = Socket::new(Protocol::Pair)?;
        // socket.bind("ipc:///tmp/ipc/pair/fibd_isisd")?;
        socket.bind("ipc:///tmp/ipc/pair/config-ng_isisd")?;
        let nanomsg = Self { socket };
        Ok(nanomsg)
    }

    fn isis_global_update(&self) -> MsgEnum {
        let msg = IsisGlobal {
            hostname: "zebra".into(),
        };
        MsgEnum::IsisGlobal(msg)
    }

    fn isis_instance_add(&self) -> MsgEnum {
        let msg = IsisInstance {
            instance_tag: "zebra".into(),
        };
        MsgEnum::IsisInstance(msg)
    }

    pub fn parse(&mut self, text: &String) -> anyhow::Result<()> {
        let value: Result<Msg, serde_json::Error> = serde_json::from_str(&text);
        match value {
            Ok(msg) => {
                println!("method {:?}", msg.method);
                if msg.method == "isis-global:request" {
                    // isis-global:update
                    let msg = MsgSend {
                        method: String::from("isis-global:update"),
                        data: self.isis_global_update(),
                    };
                    self.socket.write(to_string(&msg)?.as_bytes());
                }
                if msg.method == "isis-instance:request" {
                    // isis-instance:add
                    let msg = MsgSend {
                        method: String::from("isis-instance:add"),
                        data: self.isis_instance_add(),
                    };
                    self.socket.write(to_string(&msg)?.as_bytes());
                }
                if msg.method == "" {
                    // isis-if:add
                }
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
