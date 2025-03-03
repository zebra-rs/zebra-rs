use std::{io::Read, thread, time::Duration};

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
    IsisIf(IsisIf),
    SegmentRouting(SegmentRouting),
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
struct IsisNet {
    del: Vec<String>,
    add: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RouterId {
    #[serde(rename = "router-id")]
    router_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IsisInstance {
    #[serde(rename = "instance-tag")]
    instance_tag: String,
    #[serde(rename = "log-adjacency-changes")]
    log_adjacency_changes: bool,
    net: IsisNet,
    #[serde(rename = "is-type")]
    is_type: u32,
    #[serde(rename = "metric-style")]
    metric_style: u32,
    #[serde(rename = "segment-routing")]
    segment_routing: String,
    #[serde(rename = "mpls-traffic-eng")]
    mpls_traffic_eng: RouterId,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrefixSid {
    // index: u32,
    absolute: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct IsisIf {
    ifname: String,
    #[serde(rename = "instance-tag")]
    instance_tag: String,
    #[serde(rename = "ipv4-enable")]
    ipv4_enable: bool,
    #[serde(rename = "network-type")]
    network_type: u32,
    #[serde(rename = "circuit-type")]
    circuit_type: u32,
    #[serde(rename = "prefix-sid")]
    prefix_sid: Option<PrefixSid>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GlobalBlock {
    begin: u32,
    end: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentRouting {
    #[serde(rename = "global-block")]
    global_block: GlobalBlock,
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
        let net = IsisNet {
            del: vec![],
            add: vec!["49.0000.0000.0000.0002.00".into()],
        };
        let msg = IsisInstance {
            instance_tag: "zebra".into(),
            log_adjacency_changes: true,
            net,
            is_type: 2,
            metric_style: 2,
            segment_routing: "mpls".into(),
            mpls_traffic_eng: RouterId {
                router_id: "2.2.2.3".into(),
            },
        };
        MsgEnum::IsisInstance(msg)
    }

    fn isis_if_add_enp0s6(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "enp0s6".into(),
            instance_tag: "zebra".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: None,
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_enp0s7(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "enp0s7".into(),
            instance_tag: "zebra".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: None,
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_lo(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "lo".into(),
            instance_tag: "zebra".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: Some(PrefixSid { absolute: 16200 }),
        };
        MsgEnum::IsisIf(msg)
    }

    fn segment_routing_update(&self) -> MsgEnum {
        let msg = SegmentRouting {
            global_block: GlobalBlock {
                begin: 16000,
                end: 23999,
            },
        };
        MsgEnum::SegmentRouting(msg)
    }

    fn isis_if_add_lo_no_sid(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "lo".into(),
            instance_tag: "zebra".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: None,
        };
        MsgEnum::IsisIf(msg)
    }

    pub fn parse(&mut self, text: &str) -> anyhow::Result<()> {
        let value: Result<Msg, serde_json::Error> = serde_json::from_str(text);
        thread::sleep(Duration::from_millis(100));
        match value {
            Ok(msg) => {
                println!("method {:?}", msg.method);
                if msg.method == "isis-global:request" {
                    thread::sleep(Duration::from_secs(1));
                    // isis-global:update
                    let msg = MsgSend {
                        method: String::from("isis-global:update"),
                        data: self.isis_global_update(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
                }
                if msg.method == "isis-instance:request" {
                    // isis-instance:add
                    let msg = MsgSend {
                        method: String::from("isis-instance:add"),
                        data: self.isis_instance_add(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("isis-if:add"),
                        data: self.isis_if_add_lo(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("isis-if:add"),
                        data: self.isis_if_add_enp0s6(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("isis-if:add"),
                        data: self.isis_if_add_enp0s7(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("segment-routing:update"),
                        data: self.segment_routing_update(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    // let msg = MsgSend {
                    //     method: String::from("isis-if:add"),
                    //     data: self.isis_if_add_lo_no_sid(),
                    // };
                    // self.socket.write_all(to_string(&msg)?.as_bytes());
                }
                if msg.method == "router-id:request" {
                    println!("{}", msg.data);
                    if let Some(vrf_id) = msg.data.get("vrf-id").and_then(|v| v.as_i64()) {
                        println!("vrf-id: {}", vrf_id);
                    } else {
                        println!("no vrf-id");
                    }
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
                    self.socket.write_all(to_string(&msg)?.as_bytes());
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
        let mut text = String::new();
        loop {
            match self.socket.read_to_string(&mut text) {
                Ok(_) => {
                    println!("{}", text);
                    text.pop();
                    self.parse(&text);
                }
                Err(_err) => {
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
