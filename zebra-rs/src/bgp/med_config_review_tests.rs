//! Run alone: these callback probes change the process-wide MED policy.
//! cargo test -p zebra-rs med_config_review_tests -- --ignored --test-threads=1
use super::*;
use crate::bgp::route::{BgpRib, BgpRibType, MedPolicy};
use bgp_packet::{As4Path, EvpnPrefix, FlowspecComponent, FlowspecNlri, FlowspecPrefix, Med};
use std::str::FromStr;
use tokio::sync::mpsc;

struct RestorePolicy(MedPolicy);
impl Drop for RestorePolicy {
    fn drop(&mut self) {
        self.0.install();
    }
}

fn fresh_bgp() -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    Box::leak(Box::new(inbound_rx));
    let ctx = crate::context::ProtoContext::default_table(client);
    let (rib_tx, rib_out_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, sub_inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_out_rx));
    Box::leak(Box::new(sub_inbound_rx));
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(policy_rx));
    Bgp::new(
        ctx,
        rib_rx,
        subscriber,
        policy_tx,
        None,
        None,
        mpsc::channel(1).0,
    )
}

fn path(id: u8, asn: u32, med: Option<u32>) -> BgpRib {
    let attr = BgpAttr {
        origin: Some(bgp_packet::Origin::Igp),
        aspath: Some(As4Path::from_str(&asn.to_string()).unwrap()),
        med: med.map(Med::new),
        ..Default::default()
    };
    BgpRib::new(
        id as usize,
        Ipv4Addr::new(10, 0, 0, id),
        BgpRibType::EBGP,
        0,
        0,
        &attr,
        None,
        None,
        false,
    )
}

fn probe_untracked_families(missing_as_worst: bool) {
    let _restore = RestorePolicy(MedPolicy::current());
    MedPolicy::default().install();
    let mut bgp = fresh_bgp();
    let fs = FlowspecNlri::new(
        Afi::Ip,
        vec![FlowspecComponent::DestinationPrefix(FlowspecPrefix::V4(
            "10.10.0.0/24".parse().unwrap(),
        ))],
    );
    let rd = bgp_packet::RouteDistinguisher::default();
    let evpn = EvpnPrefix::MacIp {
        eth_tag: 0,
        mac: [2, 0, 0, 0, 0, 1],
        ip: None,
    };
    let paths = if missing_as_worst {
        [path(1, 65001, None), path(2, 65001, Some(5))]
    } else {
        [path(1, 65001, Some(10)), path(2, 65002, Some(5))]
    };
    for rib in paths {
        bgp.local_rib
            .update_flowspec(Afi::Ip, fs.clone(), rib.clone());
        let mut evpn_rib = rib;
        std::sync::Arc::make_mut(&mut evpn_rib.attr).nexthop = Some(bgp_packet::BgpNexthop::Evpn(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, evpn_rib.ident as u8)),
        ));
        bgp.local_rib.update_evpn(rd, evpn.clone(), evpn_rib);
    }
    assert_eq!(bgp.local_rib.flowspec_v4.selected[&fs].ident, 1);
    assert_eq!(bgp.local_rib.evpn[&rd].selected[&evpn].ident, 1);
    // These families legitimately have no NHT registrations.
    assert!(bgp.nexthop_cache.entries.is_empty());
    let args = Args(["true".to_string()].into_iter().collect());
    if missing_as_worst {
        config_bestpath_med_missing_as_worst(&mut bgp, args, ConfigOp::Set).unwrap();
    } else {
        config_bestpath_always_compare_med(&mut bgp, args, ConfigOp::Set).unwrap();
    }
    let cached = (
        bgp.local_rib.flowspec_v4.selected[&fs].ident,
        bgp.local_rib.evpn[&rd].selected[&evpn].ident,
    );
    // Control: the new comparator policy works when explicitly invoked.
    assert_eq!(
        bgp.local_rib.select_best_path_flowspec(Afi::Ip, &fs)[0].ident,
        2
    );
    assert_eq!(bgp.local_rib.select_best_path_evpn(&rd, &evpn)[0].ident, 2);
    assert_eq!(
        cached,
        (2, 2),
        "config must recompute FlowSpec and EVPN Type-2 immediately"
    );
    let args = Args(Default::default());
    if missing_as_worst {
        config_bestpath_med_missing_as_worst(&mut bgp, args, ConfigOp::Delete).unwrap();
    } else {
        config_bestpath_always_compare_med(&mut bgp, args, ConfigOp::Delete).unwrap();
    }
    assert_eq!(bgp.local_rib.flowspec_v4.selected[&fs].ident, 1);
    assert_eq!(bgp.local_rib.evpn[&rd].selected[&evpn].ident, 1);
}

#[tokio::test]
#[ignore = "changes process-wide MED policy; run alone with --ignored --test-threads=1"]
async fn review_probe_always_med_recomputes_untracked_families() {
    probe_untracked_families(false);
}

#[tokio::test]
#[ignore = "changes process-wide MED policy; run alone with --ignored --test-threads=1"]
async fn review_probe_missing_med_recomputes_untracked_families() {
    probe_untracked_families(true);
}

#[tokio::test]
#[ignore = "changes process-wide MED policy; run alone with --ignored --test-threads=1"]
async fn review_probe_med_recomputes_ecmp_when_winner_stays_the_same() {
    let _restore = RestorePolicy(MedPolicy::current());
    for missing_as_worst in [false, true] {
        MedPolicy::default().install();
        let mut bgp = fresh_bgp();
        let prefix = "10.10.0.0/24".parse().unwrap();
        bgp.shard.v4.2 = crate::bgp::route::MultipathCfg {
            max_paths: 2,
            relax: true,
            ..Default::default()
        };
        let paths = if missing_as_worst {
            [path(1, 65001, Some(0)), path(2, 65001, None)]
        } else {
            [path(1, 65001, Some(0)), path(2, 65002, Some(5))]
        };
        for mut rib in paths {
            let nh = std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, rib.ident as u8));
            std::sync::Arc::make_mut(&mut rib.attr).nexthop =
                Some(bgp_packet::BgpNexthop::Ipv4(match nh {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => unreachable!(),
                }));
            bgp.nexthop_cache
                .track(0, nh, crate::bgp::nht::NhtDep::V4(prefix));
            bgp.nexthop_cache
                .entries
                .get_mut(&(0, nh))
                .unwrap()
                .reachable = true;
            rib.nexthop_reachable = true;
            bgp.shard.v4.update(prefix, rib);
        }
        let members = |bgp: &Bgp| {
            bgp.shard
                .v4
                .0
                .get(&prefix)
                .unwrap()
                .iter()
                .filter(|r| r.best_path || r.multipath)
                .count()
        };
        assert_eq!(members(&bgp), 2);
        let args = Args(["true".to_string()].into_iter().collect());
        if missing_as_worst {
            config_bestpath_med_missing_as_worst(&mut bgp, args, ConfigOp::Set).unwrap();
        } else {
            config_bestpath_always_compare_med(&mut bgp, args, ConfigOp::Set).unwrap();
        }
        assert_eq!(bgp.shard.v4.1.get(&prefix).unwrap().ident, 1);
        assert_eq!(members(&bgp), 1, "ineligible ECMP leg must be removed");
        let args = Args(Default::default());
        if missing_as_worst {
            config_bestpath_med_missing_as_worst(&mut bgp, args, ConfigOp::Delete).unwrap();
        } else {
            config_bestpath_always_compare_med(&mut bgp, args, ConfigOp::Delete).unwrap();
        }
        assert_eq!(bgp.shard.v4.1.get(&prefix).unwrap().ident, 1);
        assert_eq!(members(&bgp), 2, "deleting the knob must restore ECMP");
    }
}
