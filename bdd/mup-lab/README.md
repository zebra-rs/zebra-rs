# mup-lab — free5GC + free-ran-ue + zebra-rs/cradle single-box UPF

The manual lab that first proved end-to-end UE ping through zebra-rs +
cradle acting as the UPF (`afi-safi mup dataplane gtp`), against a real
5G core (free5GC v4.0.1) and a real RAN/UE simulator (free-ran-ue), on
2026-07-14 (issue #1930). Since issue #1947 the lab uses the
telco-normal **single-N6** shape: ONE VRF binds both `route st1` and
`route st2`, so the UPF has one N6-facing interface — uplink and
downlink are directions of the same N6 network. The distilled,
self-contained regression lives in cradle-rs as the
`@cradle_mup_gtp_single_n6` BDD feature (the two-leg original remains
as `@cradle_mup_gtp_roundtrip`); this lab is for reproducing the full
free5GC stack by hand.

```
 host (root netns): free5GC CP on 127.0.0.x SBI, mongodb, webconsole
  ├─ mrHost 10.0.1.1/24  ── veth ──  mupran: mrVeth 10.0.1.2/24   (N2 + N3 transit)
  ├─ muHost 10.0.12.1/24 ── veth ──  mupupf: mun3  10.0.12.2/24   (N4 + N3)
  └─ ip_forward=1 between the two /24s

 mupran: free-ran-ue gNB (N2/N3 on 10.0.1.2; UE link on 127.0.0.1) + UE (ueTun0)
 mupupf: zebra-rs + cradle
          VRF mobile (table 1, st1+st2): mun6 10.0.60.1/24 ── mupdn: mdn6 10.0.60.2
 mupdn:  route 10.60.0.0/16 (the free5GC UE pool) via 10.0.60.1
```

Key design points

- **N3 lives in the global table**; the MUP VRF only anchors the
  st1/st2 routes. **One VRF binds BOTH directions** (zebra-rs PR #2038,
  issue #1947): its single cradle table holds the uplink decap PDR, the
  downlink UE-prefix encap route and the N6 connected route together,
  so one N6 leg carries downlink ingress and uplink egress. (The older
  one-direction-per-VRF split still works — two VRFs, two legs — but is
  no longer required.)
- **PFCP `listen-address` = the N3 address** (10.0.12.2): the
  controller's N4 identity doubles as the F-TEID address fallback, so
  one address keeps the tunnel endpoint consistent.
- **`network-instance` = the DNN** free5GC puts in the PDI Network
  Instance (`internet`); the same NI on both `route` bindings makes one
  PFCP session fan out to both ST routes.
- free5GC allocates the UPF's N3 TEID itself (Create PDR → PDI local
  F-TEID, TS 29.244 CH=0) and ignores the Created-PDR F-TEID; mup-c
  honors it as authoritative (commit `eb576cf9`).
- The free-ran-ue gNB sends uplink GTP-U to `upfN3Ip` **from its config**
  (it ignores the NGAP transport address), and its UE process needs root
  for the TUN device.

## Prerequisites

```sh
# Install zebra-rs (needs the dual-direction `afi-safi mup route` binding, PR #2038)

# Install cradle (version >= 0.9.7)

# free5GC v4.0.1 CP NFs + webconsole backend (Go >= 1.21; no gtp5g needed — we ARE the UPF)
cd ~/free5gc && make nrf smf udr udm ausf nssf pcf chf   # amf: use prebuilt bin/amf
cd webconsole && go build -o bin/webconsole server.go

# free-ran-ue (Go 1.26 via auto-toolchain; needs the N3 crash fix, PR free-ran-ue#326)
# Until #326 merges upstream, apply the bundled patch to a vanilla checkout.
# PATCH points at this lab directory (bdd/mup-lab), which ships the .patch:
PATCH=/path/to/zebra-rs/bdd/mup-lab/free-ran-ue-0001-gnb-n3-read-error-crash-fix.patch
cd ~/free-ran-ue
git am "$PATCH"                       # or: patch -p1 < "$PATCH" for a non-git tree
# (already have the fix — e.g. commit 4d9a793 on your branch — skip the patch)
make bin

# MongoDB (Ubuntu's 3.6 package works)
sudo mkdir -p /var/log/mongodb /var/lib/mongodb
sudo chown mongodb:mongodb /var/log/mongodb /var/lib/mongodb
sudo systemctl start mongodb
```

Provision the default subscriber (matches `ue.yaml`: IMSI
208930000000001, the classic free5GC demo K/OPc):

```sh
cd ~/free5gc/webconsole && ./bin/webconsole -c ../config/webuicfg.yaml &
TOKEN=$(curl -s -X POST http://127.0.0.1:5000/api/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"free5gc"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST "http://127.0.0.1:5000/api/subscriber/imsi-208930000000001/20893" \
  -H "Token: $TOKEN" -H 'Content-Type: application/json' \
  -d @/home/kunihiro/free-ran-ue/script/10k-test-script/free5gc-console-subscriber-data.json
```

## Bring-up (order matters)

```sh
LAB=$(pwd)   # this directory
mkdir -p $LAB/logs

# 1. topology
sudo $LAB/setup-topo.sh

# 2. cradle, then zebra-rs, in the UPF namespace (zebra tees to unix:cradle/grpc)
sudo ip netns exec mupupf sh -c "RUST_LOG=info,cradle=debug exec ~/cradle-rs/target/debug/cradle \
  serve --config $LAB/upf-ports.json --grpc unix:cradle/grpc \
  --pid-file /tmp/mupupf_cradle.pid >> $LAB/logs/cradle.log 2>&1 &"
sudo ip netns exec mupupf sh -c "RUST_LOG=info exec $(git rev-parse --show-toplevel)/target/debug/zebra-rs \
  --yang-path $(git rev-parse --show-toplevel)/zebra-rs/yang --config-file $LAB/upf.yaml \
  --log-output=file --log-file=$LAB/logs/zebra.log \
  --pid-file /tmp/mupupf_zebra.pid >> $LAB/logs/zebra.stdout 2>&1 &"

# 3. free5GC CP on the host (lab amfcfg/smfcfg; defaults for the rest)
cd ~/free5gc
for nf in nrf amf smf udr pcf udm nssf ausf; do
  cfg=config/${nf}cfg.yaml
  [ $nf = amf ] && cfg=$LAB/amfcfg.yaml
  [ $nf = smf ] && cfg=$LAB/smfcfg.yaml
  (./bin/$nf -c $cfg > $LAB/logs/$nf.log 2>&1 &); sleep 1
done
# SMF associates with the UPF within seconds:
#   "UPF(10.0.12.2) setup association" in logs/smf.log

# 4. gNB, then UE, in the RAN namespace (UE creates ueTun0; needs root)
sudo ip netns exec mupran sh -c "exec ~/free-ran-ue/build/free-ran-ue gnb -c $LAB/gnb.yaml \
  > $LAB/logs/gnb.log 2>&1 &"
sleep 3
sudo ip netns exec mupran sh -c "exec ~/free-ran-ue/build/free-ran-ue ue -c $LAB/ue.yaml \
  > $LAB/logs/ue.log 2>&1 &"
```

Quirk: if the UE log stalls at "Processing PDU session establishment"
(a stale SM context from a previous run racing its release), kill just
the UE process and start it again — the second attach goes through.

## Verify, then ping

```sh
V=$(git rev-parse --show-toplevel)/target/debug/vtyctl
sudo ip netns exec mupupf $V show 'show bgp mup-c association'   # SMF peer
sudo ip netns exec mupupf $V show 'show bgp mup-c session'       # UE addr, Access + Core F-TEIDs
sudo ip netns exec mupupf $V show 'show bgp vrf mobile mup'      # BOTH: [ST1] ue=<UE>/32 -> gNB
                                                                 #  and  [ST2] ep=10.0.12.2, CP TEID
sudo ip netns exec mupupf bpftool map dump name GTP_PDR           # uplink decap key
sudo ip netns exec mupupf ~/cradle-rs/target/debug/cradle dump ipv4 --grpc unix:cradle/grpc --vrf 1
# ^ table 1 now holds the UE /32 GTP encap route AND the 10.0.60.0/24 connected route

# seed ARP once, then the end-to-end ping through the single N6 leg
sudo ip netns exec mupdn  ping -c1 -W1 10.0.60.1 >/dev/null
sudo ip netns exec mupupf ping -c1 -W1 10.0.12.1 >/dev/null
sudo ip netns exec mupran ping -I ueTun0 -c 5 10.0.60.2

sudo ip netns exec mupupf ~/cradle-rs/target/debug/cradle stats --grpc unix:cradle/grpc | grep gtp
```

Expected: 0% loss, and `gtp_encap` / `gtp_decap` both counting.

## iperf3 (issue #1947's single-NIC throughput check)

Two things `ping -I ueTun0` silently papered over:

- the UE netns has **no route to the DN via the TUN** (free-ran-ue only
  assigns the address) — a TCP connect follows the default route out
  mrVeth and dies. Add the route explicitly.
- the DN veth's **TX checksum offload** leaves TCP checksums
  uncomputed; cradle's GTP encap forwards the raw bytes and the UE TUN
  validates (and drops) them. `setup-topo.sh` turns it off (`ethtool -K
  mdn6 tx off`); hardware NICs don't have this problem.

```sh
# server on the N6 side, client on the UE TUN. The UE address comes from
# the free5GC pool (10.60.0.0/16), so bind the client to it explicitly.
UEADDR=$(sudo ip netns exec mupran ip -o -4 addr show ueTun0 | awk '{print $4}' | cut -d/ -f1)
sudo ip netns exec mupran ip route add 10.0.60.0/24 dev ueTun0 src $UEADDR
# GTP adds 36 bytes on N3; keep TCP MSS inside the 1500-byte links:
sudo ip netns exec mupran ip link set ueTun0 mtu 1400

sudo ip netns exec mupdn iperf3 -s -D -1
sudo ip netns exec mupran iperf3 -c 10.0.60.2 -B $UEADDR -t 5 -f m       # uplink
sudo ip netns exec mupdn iperf3 -s -D -1
sudo ip netns exec mupran iperf3 -c 10.0.60.2 -B $UEADDR -t 5 -f m -R    # downlink
sudo ip netns exec mupupf ~/cradle-rs/target/debug/cradle stats --grpc unix:cradle/grpc | grep gtp
```

Measured on the 2026-07-20 validation run (single box, debug builds,
free-ran-ue's userspace gNB in the path): **uplink ~1.86 Gbit/s,
downlink ~2.65 Gbit/s**, `gtp_encap`/`gtp_decap` in the hundreds of
thousands.

Known gap: if you restart *cradle* under a live zebra-rs, the tee does
not replay its mirror (tonic reconnects transparently) — restart
zebra-rs instead, wait for the SMF to re-associate, and re-attach the UE.

## Teardown

```sh
sudo $LAB/teardown-topo.sh
for nf in nrf amf smf udr pcf udm nssf ausf webconsole; do pkill -x $nf; done
sudo systemctl stop mongodb
```
