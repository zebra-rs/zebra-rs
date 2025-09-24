use std::{io::Read, net::Ipv4Addr, thread, time::Duration};

use nanomsg::{Protocol, Socket};
use serde::{Deserialize, Serialize};
use serde_json::{Value, from_value, to_string};

struct Nanomsg {
    socket: Socket,
}

#[derive(Debug, Serialize, Deserialize)]
struct Msg {
    method: String,
    data: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VrfWrapper {
    #[serde(rename = "vrf-name")]
    vrf_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MsgWrapper {
    method: String,
    data: VrfWrapper,
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
    IsisIfDel(IsisIfDel),
    SegmentRouting(SegmentRouting),
    BgpGlobal(BgpGlobal),
    BgpInstance(BgpInstance),
    BgpNeighbor(BgpNeighbor),
    Vrf(Vrf),
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
struct AddressFamily {
    #[serde(rename = "ti-lfa")]
    ti_lfa: bool,
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
    #[serde(rename = "mpls-traffic-eng", skip_serializing_if = "Option::is_none")]
    mpls_traffic_eng: Option<RouterId>,
    #[serde(rename = "ipv4 unicast")]
    ipv4_unicast: AddressFamily,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrefixSid {
    index: u32,
    // absolute: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct IsisIfLevel {
    metric: u32,
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
    #[serde(rename = "prefix-sid", skip_serializing_if = "Option::is_none")]
    prefix_sid: Option<PrefixSid>,
    #[serde(rename = "adjacency-sid", skip_serializing_if = "Option::is_none")]
    adjacency_sid: Option<PrefixSid>,
    #[serde(rename = "srlg-group")]
    srlg_group: String,
    #[serde(rename = "l2-config")]
    l2_config: Option<IsisIfLevel>,
}

#[derive(Debug, Serialize, Deserialize)]
struct IsisIfDel {
    ifname: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GlobalBlock {
    begin: u32,
    end: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalBlock {
    begin: u32,
    end: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentRouting {
    #[serde(rename = "global-block")]
    global_block: GlobalBlock,
    #[serde(rename = "local-block")]
    local_block: LocalBlock,
}

#[derive(Debug, Serialize, Deserialize)]
struct BgpGlobal {
    #[serde(rename = "4octet-asn")]
    four_octet_asn: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Redistribute {
    #[serde(rename = "type")]
    typ: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct RedistributeAf {
    ipv4: Vec<Redistribute>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BgpInstance {
    #[serde(rename = "vrf-id")]
    vrf_id: u32,
    #[serde(rename = "as")]
    asn: u32,
    instance: u32,
    #[serde(rename = "router-id")]
    router_id: Ipv4Addr,
    redistribute: RedistributeAf,
    #[serde(rename = "route-target-in")]
    route_target_in: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BgpNeighbor {
    #[serde(rename = "vrf-id")]
    vrf_id: u32,
    #[serde(rename = "bgp-instance")]
    bgp_instance: u32,
    address: Ipv4Addr,
    #[serde(rename = "remote-as")]
    remote_as: u32,
    #[serde(rename = "local-as")]
    local_as: u32,
    #[serde(rename = "address-family")]
    address_family: Vec<BgpAddressFamily>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BgpAddressFamily {
    afi: u32,
    safi: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vrf {
    #[serde(rename = "vrf-id")]
    vrf_id: u32,
    #[serde(rename = "vrf-name")]
    vrf_name: String,
    #[serde(rename = "route-distinguisher")]
    rd: String,
}

use std::io::Write;

impl Nanomsg {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let mut socket = Socket::new(Protocol::Pair)?;
        socket.bind(path)?;
        let nanomsg = Self { socket };
        Ok(nanomsg)
    }

    fn isis_global_update(&self) -> MsgEnum {
        let msg = IsisGlobal {
            hostname: "s".into(),
        };
        MsgEnum::IsisGlobal(msg)
    }

    fn isis_instance_add(&self) -> MsgEnum {
        let net = IsisNet {
            del: vec![],
            add: vec!["49.0000.0000.0000.0001.00".into()],
        };
        let msg = IsisInstance {
            instance_tag: "s".into(),
            log_adjacency_changes: true,
            net,
            is_type: 2,
            metric_style: 2,
            segment_routing: "mpls".into(),
            mpls_traffic_eng: Some(RouterId {
                router_id: "10.0.0.1".into(),
            }),
            ipv4_unicast: AddressFamily { ti_lfa: true },
        };
        MsgEnum::IsisInstance(msg)
    }

    fn isis_instance_add2(&self) -> MsgEnum {
        let net = IsisNet {
            del: vec![],
            add: vec!["49.0000.0000.0000.0001.00".into()],
        };
        let msg = IsisInstance {
            instance_tag: "s".into(),
            log_adjacency_changes: true,
            net,
            is_type: 2,
            metric_style: 2,
            segment_routing: "mpls".into(),
            mpls_traffic_eng: Some(RouterId {
                router_id: "9.9.9.9".into(),
            }),
            ipv4_unicast: AddressFamily { ti_lfa: true },
        };
        MsgEnum::IsisInstance(msg)
    }

    fn isis_if_add_enp0s6_none(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "enp0s6".into(),
            instance_tag: "s".into(),
            ipv4_enable: true,
            network_type: 2,
            circuit_type: 2,
            prefix_sid: None,
            adjacency_sid: None,
            srlg_group: "group-1".into(),
            l2_config: Some(IsisIfLevel { metric: 20 }),
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_enp0s6(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "enp0s6".into(),
            instance_tag: "s".into(),
            ipv4_enable: true,
            network_type: 2,
            circuit_type: 2,
            prefix_sid: None,
            adjacency_sid: Some(PrefixSid { index: 100 }),
            srlg_group: "group-1".into(),
            l2_config: Some(IsisIfLevel { metric: 20 }),
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_enp0s7(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "enp0s7".into(),
            instance_tag: "s".into(),
            ipv4_enable: true,
            network_type: 2,
            circuit_type: 2,
            prefix_sid: None,
            adjacency_sid: Some(PrefixSid { index: 200 }),
            srlg_group: "group-1".into(),
            l2_config: Some(IsisIfLevel { metric: 20 }),
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_lo(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "lo".into(),
            instance_tag: "s".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: Some(PrefixSid { index: 100 }),
            adjacency_sid: None,
            srlg_group: "".into(),
            l2_config: None,
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_add_lo_none(&self) -> MsgEnum {
        let msg = IsisIf {
            ifname: "lo".into(),
            instance_tag: "s".into(),
            ipv4_enable: true,
            network_type: 1,
            circuit_type: 2,
            prefix_sid: None,
            adjacency_sid: None,
            srlg_group: "".into(),
            l2_config: None,
        };
        MsgEnum::IsisIf(msg)
    }

    fn isis_if_del_lo(&self) -> MsgEnum {
        let msg = IsisIfDel {
            ifname: "lo".into(),
        };
        MsgEnum::IsisIfDel(msg)
    }

    fn segment_routing_update(&self) -> MsgEnum {
        let msg = SegmentRouting {
            global_block: GlobalBlock {
                begin: 16000,
                end: 23999,
            },
            local_block: LocalBlock {
                begin: 15000,
                end: 15999,
            },
        };
        MsgEnum::SegmentRouting(msg)
    }

    fn bgp_global(&self) -> MsgEnum {
        let msg = BgpGlobal {
            four_octet_asn: true,
        };
        MsgEnum::BgpGlobal(msg)
    }

    fn bgp_instance(&self) -> MsgEnum {
        let router_id = "10.0.0.1".parse::<Ipv4Addr>().unwrap();
        let redist = Redistribute { typ: 1 };
        let redistribute = RedistributeAf { ipv4: vec![redist] };
        let msg = BgpInstance {
            vrf_id: 0,
            asn: 65501,
            instance: 1,
            router_id: router_id,
            redistribute,
            route_target_in: vec![],
        };
        MsgEnum::BgpInstance(msg)
    }

    fn bgp_vrf(&self) -> MsgEnum {
        let router_id = "192.168.10.1".parse::<Ipv4Addr>().unwrap();
        let redist = Redistribute { typ: 1 };
        let redistribute = RedistributeAf { ipv4: vec![redist] };
        let msg = BgpInstance {
            vrf_id: 1,
            asn: 65501,
            instance: 2,
            router_id: router_id,
            redistribute,
            route_target_in: vec!["1:1".to_string()],
        };
        MsgEnum::BgpInstance(msg)
    }

    fn bgp_neighbor(&self) -> MsgEnum {
        let address = "192.168.2.2".parse::<Ipv4Addr>().unwrap();
        let ipv4_uni = BgpAddressFamily { afi: 1, safi: 1 };
        let vpnv4_uni = BgpAddressFamily { afi: 1, safi: 4 };
        let msg = BgpNeighbor {
            vrf_id: 0,
            bgp_instance: 1,
            address,
            remote_as: 65501,
            local_as: 65501,
            address_family: vec![ipv4_uni, vpnv4_uni],
        };
        MsgEnum::BgpNeighbor(msg)
    }

    fn vrf(&self) -> MsgEnum {
        let msg = Vrf {
            vrf_id: 1,
            vrf_name: "vrf1".to_string(),
            rd: "1:1".to_string(),
        };
        MsgEnum::Vrf(msg)
    }

    pub fn parse(&mut self, text: &str) -> anyhow::Result<()> {
        let value: Result<Msg, serde_json::Error> = serde_json::from_str(text);
        thread::sleep(Duration::from_millis(100));
        match value {
            Ok(msg) => {
                println!("method {:?}", msg.method);
                if msg.method == "bgp-global:request" {
                    let msg = MsgSend {
                        method: String::from("vrf:add"),
                        data: self.vrf(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
                    println!("BGP Global");
                    let msg = MsgSend {
                        method: String::from("bgp-global:update"),
                        data: self.bgp_global(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
                }
                if msg.method == "bgp-instance:request" {
                    let msg = MsgSend {
                        method: String::from("bgp-instance:add"),
                        data: self.bgp_instance(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    println!("BGP Neighbor");
                    let msg = MsgSend {
                        method: String::from("bgp-neighbor:add"),
                        data: self.bgp_neighbor(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let vrf: MsgWrapper = serde_json::from_str(text).unwrap();
                    println!("BGP Instance for VRF {}", vrf.data.vrf_name);
                    let msg = MsgSend {
                        method: String::from("bgp-instance:add"),
                        data: self.bgp_vrf(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
                }
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
                    let msg = MsgSend {
                        method: String::from("segment-routing:update"),
                        data: self.segment_routing_update(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
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
                        data: self.isis_if_add_enp0s6_none(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("isis-if:add"),
                        data: self.isis_if_add_enp0s7(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    let msg = MsgSend {
                        method: String::from("isis-instance:add"),
                        data: self.isis_instance_add2(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());

                    // let msg = MsgSend {
                    //     method: String::from("isis-if:delete"),
                    //     data: self.isis_if_del_lo(),
                    // };
                    // self.socket.write_all(to_string(&msg)?.as_bytes());

                    thread::sleep(Duration::from_secs(6));

                    let msg = MsgSend {
                        method: String::from("isis-if:add"),
                        data: self.isis_if_add_enp0s6(),
                    };
                    self.socket.write_all(to_string(&msg)?.as_bytes());
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
    let nanomsg = Nanomsg::new("ipc:///tmp/ipc/pair/config-ng_isisd");
    if let Ok(mut nanomsg) = nanomsg {
        tokio::spawn(async move {
            nanomsg.event_loop().await;
        });
    }
    let nanomsg = Nanomsg::new("ipc:///tmp/ipc/pair/config-ng_bgpd");
    if let Ok(mut nanomsg) = nanomsg {
        tokio::spawn(async move {
            nanomsg.event_loop().await;
        });
    }
}
