#!/usr/bin/env python3
"""Exercise EVPN using only Linux namespaces and two zebra-rs speakers."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import time
import uuid


REPO = Path(__file__).resolve().parents[2]


def run(*args, check=True):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zebra', type=Path, default=REPO / 'target/debug/zebra-rs')
    parser.add_argument('--vtyctl', type=Path, default=REPO / 'target/debug/vtyctl')
    parser.add_argument('--yang', type=Path, default=REPO / 'zebra-rs/yang')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ipv6-vtep', action='store_true',
                        help='use IPv6 VTEPs over an IPv6 underlay')
    args = parser.parse_args()

    def vtep(i):
        return f'2001:db8:100::{i}' if args.ipv6_vtep else f'198.51.100.{i}'

    def rmac_gateways(i):
        # The RMAC neighbors a bridge Type-5 route through VTEP i needs.
        if args.ipv6_vtep:
            return [('-6', vtep(i))]
        return [('-4', vtep(i)), ('-6', f'::ffff:{vtep(i)}')]

    def v6_adjacency(i):
        return rmac_gateways(i)[-1][1]
    if os.geteuid() != 0:
        parser.error('run with sudo; this creates and removes isolated network namespaces')
    tag = 'ek' + uuid.uuid4().hex[:6]
    namespaces = []
    processes = []
    logs = []
    checks = []
    report = {'binary_sha256': hashlib.sha256(args.zebra.read_bytes()).hexdigest(),
              'vtep_family': 'IPv6' if args.ipv6_vtep else 'IPv4',
              'checks': checks, 'dataplane': 'Linux bridge/VXLAN/VRF',
              'dependencies': ['iproute2', 'zebra-rs', 'vtyctl']}

    def ns(name, *command, check=True):
        return run('ip', 'netns', 'exec', tag + '-' + name, *command, check=check)

    def link(a, b, a_if, b_if, serial):
        left, right = tag + 'a' + str(serial), tag + 'b' + str(serial)
        run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        run('ip', 'link', 'set', left, 'netns', tag + '-' + a)
        run('ip', 'link', 'set', right, 'netns', tag + '-' + b)
        for node, old, new in [(a, left, a_if), (b, right, b_if)]:
            ns(node, 'ip', 'link', 'set', old, 'name', new)
            ns(node, 'ip', 'link', 'set', new, 'up')

    def expect(name, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        error = ''
        while time.monotonic() < deadline:
            try:
                if predicate():
                    checks.append({'name': name, 'passed': True})
                    print('PASS:', name, flush=True)
                    return
            except (subprocess.CalledProcessError, ValueError) as exc:
                error = str(exc)
            time.sleep(0.2)
        checks.append({'name': name, 'passed': False, 'error': error})
        raise RuntimeError('failed: ' + name)

    def show(node, command):
        return ns(node, str(args.vtyctl), 'show', command).stdout

    def route(node, prefix):
        family = '-6' if ':' in prefix else '-4'
        return json.loads(ns(node, 'ip', family, '-j', 'route', 'show',
                             'table', '100', 'exact', prefix).stdout)

    def main_route(node, prefix):
        family = '-6' if ':' in prefix else '-4'
        return json.loads(ns(node, 'ip', family, '-j', 'route', 'show',
                             'exact', prefix).stdout)

    def start(v, config, log, *extra):
        return subprocess.Popen(['ip', 'netns', 'exec', tag + '-' + v,
                                 str(args.zebra), '--yang-path', str(args.yang),
                                 '--config-file', str(config), *extra],
                                stdout=log, stderr=log)

    configs = {}
    try:
        with tempfile.TemporaryDirectory(prefix=tag + '-') as directory:
            directory = Path(directory)
            for name in ['v1', 'v2', 'l1', 'l2', 'r1', 'r2']:
                run('ip', 'netns', 'add', tag + '-' + name)
                namespaces.append(tag + '-' + name)
                ns(name, 'ip', 'link', 'set', 'lo', 'up')
                ns(name, 'sysctl', '-qw', 'net.ipv6.conf.all.disable_ipv6=0')
            link('v1', 'v2', 'underlay', 'underlay', 0)
            for i in [1, 2]:
                v, l, r = 'v' + str(i), 'l' + str(i), 'r' + str(i)
                link(v, l, 'access', 'eth0', i)
                link(v, r, 'routed', 'eth0', i + 2)
                ns(v, 'sysctl', '-qw', 'net.ipv4.ip_forward=1',
                   'net.ipv6.conf.all.forwarding=1', 'net.ipv4.conf.all.rp_filter=0')
                ns(v, 'ip', 'address', 'add', f'192.0.2.{i}/24', 'dev', 'underlay')
                ns(v, 'ip', '-6', 'address', 'add', f'2001:db8:ff::{i}/64', 'dev', 'underlay', 'nodad')
                if args.ipv6_vtep:
                    ns(v, 'ip', '-6', 'address', 'add', vtep(i) + '/128', 'dev', 'lo')
                    ns(v, 'ip', '-6', 'address', 'add', f'2001:db8:101::{i}/64', 'dev', 'underlay', 'nodad')
                    ns(v, 'ip', '-6', 'route', 'add', vtep(3-i) + '/128',
                       'via', f'2001:db8:101::{3-i}', 'proto', 'static')
                else:
                    ns(v, 'ip', 'address', 'add', vtep(i) + '/32', 'dev', 'lo')
                    ns(v, 'ip', 'route', 'add', vtep(3-i) + '/32',
                       'via', f'192.0.2.{3-i}', 'proto', 'static')
                ns(v, 'ip', 'link', 'add', 'tenant100', 'type', 'vrf', 'table', '100')
                ns(v, 'ip', 'link', 'set', 'tenant100', 'up')
                for vni in [1000, 2000]:
                    bridge, vxlan = f'br{vni}', f'vx{vni}'
                    ns(v, 'ip', 'link', 'add', bridge, 'type', 'bridge')
                    ns(v, 'ip', 'link', 'set', bridge, 'address', f'02:00:00:00:{vni//1000:02x}:{i:02x}')
                    if vni == 2000:
                        ns(v, 'ip', 'link', 'set', bridge, 'master', 'tenant100')
                    ns(v, 'ip', 'link', 'set', bridge, 'up')
                    ns(v, 'ip', 'link', 'add', vxlan, 'type', 'vxlan', 'id', str(vni),
                       'local', vtep(i), 'dstport', '4789', 'nolearning')
                    ns(v, 'ip', 'link', 'set', vxlan, 'master', bridge)
                    ns(v, 'ip', 'link', 'set', vxlan, 'up')
                ns(v, 'ip', 'link', 'set', 'access', 'master', 'br1000')
                ns(v, 'ip', 'address', 'add', f'10.10.0.{i}/24', 'dev', 'br1000')
                ns(v, 'ip', '-6', 'address', 'add', f'2001:db8:10::{i}/64', 'dev', 'br1000', 'nodad')
                ns(l, 'ip', 'link', 'set', 'eth0', 'address', f'02:00:00:10:00:{i:02x}')
                ns(l, 'ip', 'address', 'add', f'10.10.0.{100+i}/24', 'dev', 'eth0')
                ns(l, 'ip', '-6', 'address', 'add', f'2001:db8:10::{100+i}/64', 'dev', 'eth0', 'nodad')
                ns(v, 'ip', 'link', 'set', 'routed', 'master', 'tenant100')
                ns(v, 'ip', 'address', 'add', f'10.20.{i}.1/24', 'dev', 'routed')
                ns(v, 'ip', '-6', 'address', 'add', f'2001:db8:20:{i}::1/64', 'dev', 'routed', 'nodad')
                ns(r, 'ip', 'address', 'add', f'10.20.{i}.10/24', 'dev', 'eth0')
                ns(r, 'ip', '-6', 'address', 'add', f'2001:db8:20:{i}::10/64', 'dev', 'eth0', 'nodad')
                ns(r, 'ip', 'route', 'add', 'default', 'via', f'10.20.{i}.1')
                ns(r, 'ip', '-6', 'route', 'add', 'default', 'via', f'2001:db8:20:{i}::1')
                # Generic static discard routes, present before daemon startup.
                ns(v, 'ip', 'route', 'add', 'blackhole', f'10.30.{i}.0/24', 'table', '100', 'proto', 'static')
                ns(v, 'ip', '-6', 'route', 'add', 'blackhole', f'2001:db8:30:{i}::/64', 'table', '100', 'proto', 'static')
                if i == 1:
                    # Withdrawn while v2 is down, to leave v2 a VRF BGP leftover.
                    ns(v, 'ip', 'route', 'add', 'blackhole', '10.31.1.0/24', 'table', '100', 'proto', 'static')
                else:
                    # An operator's main-table route: never a zebra-rs leftover.
                    ns(v, 'ip', 'route', 'add', 'blackhole', '10.98.0.0/24', 'proto', 'static')
                lines = [f'set system hostname {v}', 'set router bgp global as 65000',
                         f'set router bgp global router-id 192.0.2.{i}',
                         'set router bgp afi-safi evpn advertise-all-vni true',
                         'set router bgp afi-safi evpn kernel-route-exchange true',
                         f'set router bgp neighbor 192.0.2.{3-i} enabled true',
                         f'set router bgp neighbor 192.0.2.{3-i} remote-as 65000',
                         f'set router bgp neighbor 192.0.2.{3-i} afi-safi evpn enabled true',
                         f'set router bgp vrf tenant100 rd 65000:{2000+i}',
                         'set router bgp vrf tenant100 encapsulation vxlan',
                         'set router bgp vrf tenant100 evpn l3vni 2000',
                         f'set router bgp vrf tenant100 evpn router-mac 02:00:00:00:02:{i:02x}']
                for af in ['ipv4', 'ipv6']:
                    lines += [f'set vrf tenant100 {af} route-target import 65000:2000',
                              f'set vrf tenant100 {af} route-target export 65000:2000',
                              f'set router bgp vrf tenant100 evpn advertise-{af} true',
                              f'set router bgp vrf tenant100 afi-safi {af} redistribute kernel']
                lines += [f'set router bgp vrf tenant100 afi-safi ipv4 network 10.20.{i}.0/24',
                          f'set router bgp vrf tenant100 afi-safi ipv6 network 2001:db8:20:{i}::/64']
                if i == 2:
                    lines += ['set router static ipv4 route 10.99.1.0/24 nexthop blackhole',
                              'set router static ipv4 route 10.99.2.0/24 nexthop blackhole',
                              'set router static ipv6 route 2001:db8:99:1::/64 nexthop blackhole']
                    for af, prefixes, gateways in [
                        ('ipv4', ['10.99.3.0/24', '10.99.4.0/24'], ['192.0.2.1', '192.0.2.3']),
                        ('ipv6', ['2001:db8:99:3::/64', '2001:db8:99:4::/64'],
                         ['2001:db8:ff::1', '2001:db8:ff::3']),
                    ]:
                        for prefix in prefixes:
                            for gateway, metric in zip(gateways, [100, 200]):
                                lines.append(f'set router static {af} route {prefix} nexthop {gateway} metric {metric}')
                config = directory / (v + '.conf')
                config.write_text('\n'.join(lines) + '\n')
                configs[v] = lines
                log = (directory / (v + '.log')).open('w+')
                logs.append((v, log))
                processes.append(start(v, config, log))

            for i in [1, 2]:
                v = 'v' + str(i)
                expect(v + ' EVPN established', lambda v=v: 'Estab' in show(v, 'show bgp summary'))
                ns('l' + str(i), 'ping', '-c', '1', '-W', '2', f'10.10.0.{i}')
                ns('l' + str(i), 'ping', '-6', '-c', '1', '-W', '2', f'2001:db8:10::{i}')

            for i in [1, 2]:
                v, peer = 'v' + str(i), 3-i
                for af, address in [('-4', f'10.10.0.{100+peer}'), ('-6', f'2001:db8:10::{100+peer}')]:
                    expect(f'{v} Type-2 {af} neighbor', lambda v=v, af=af, address=address:
                           'extern_learn' in ns(v, 'ip', af, 'neighbor', 'show', address, 'dev', 'br1000').stdout)
                    expect(f'l{i} switched {af}', lambda i=i, af=af, address=address:
                           ns('l'+str(i), 'ping', af, '-c', '1', '-W', '1', address, check=False).returncode == 0)
                expect(f'{v} preserved VTEP', lambda v=v, peer=peer:
                       f'dst {vtep(peer)}' in ns(v, 'bridge', 'fdb', 'show', 'dev', 'vx1000').stdout)
                expect(f'{v} Type-3 IMET', lambda v=v, peer=peer:
                       f'[3]:[0]:[{128 if args.ipv6_vtep else 32}]:[{vtep(peer)}]' in show(v, 'show bgp evpn'))
                expect(f'{v} mapped IPv6 RMAC adjacency', lambda v=v, peer=peer:
                       'extern_learn' in ns(v, 'ip', '-6', 'neighbor', 'show',
                                           v6_adjacency(peer), 'dev', 'br2000').stdout)
                for prefix in [f'10.20.{peer}.0/24', f'2001:db8:20:{peer}::/64',
                               f'10.30.{peer}.0/24', f'2001:db8:30:{peer}::/64']:
                    expect(f'{v} Type-5 {prefix}', lambda v=v, prefix=prefix:
                           any(r.get('dev') == 'br2000' and r.get('protocol') == 'bgp' for r in route(v, prefix)))
                for af, address in [('-4', f'10.20.{peer}.10'), ('-6', f'2001:db8:20:{peer}::10')]:
                    expect(f'r{i} routed {af}', lambda i=i, af=af, address=address:
                           ns('r'+str(i), 'ping', af, '-c', '1', '-W', '1', address, check=False).returncode == 0)

            # ARP/ND suppression: with neigh_suppress on the VXLAN port and
            # the remote MAC/IP binding installed as a neighbor on the
            # bridge, v1 answers l1's ARP request and IPv6 neighbor
            # solicitation for l2 itself; neither enters the overlay.
            if shutil.which('tcpdump'):
                capture = Path(directory) / 'suppress.txt'
                with capture.open('w') as out:
                    tcpdump = subprocess.Popen(
                        ['ip', 'netns', 'exec', tag + '-v1', 'timeout', '6', 'tcpdump',
                         '-nli', 'vx1000', 'arp or icmp6'],
                        stdout=out, stderr=subprocess.DEVNULL)
                    time.sleep(1)
                    ns('l1', 'ip', 'neighbor', 'flush', 'dev', 'eth0')
                    resolved = {af: ns('l1', 'ping', af, '-c', '1', '-W', '2', address,
                                       check=False).returncode == 0
                                for af, address in [('-4', '10.10.0.102'), ('-6', '2001:db8:10::102')]}
                    tcpdump.wait()
                frames = capture.read_text()
                for af, address in [('-4', '10.10.0.102'), ('-6', '2001:db8:10::102')]:
                    expect(f'ARP/ND suppression {af}: l1 resolves l2', lambda af=af: resolved[af], timeout=1)
                expect('ARP suppression: no ARP request for l2 enters the overlay', lambda:
                       'who-has 10.10.0.102' not in frames, timeout=1)
                expect('ND suppression: no neighbor solicitation for l2 enters the overlay', lambda:
                       'who has 2001:db8:10::102' not in frames, timeout=1)
            else:
                checks.append({'name': 'ARP/ND suppression', 'passed': True, 'skipped': 'no tcpdump'})
                print('SKIP: ARP/ND suppression (no tcpdump)', flush=True)

            # The kernel drops bridge Type-5 state on its own: admin-down
            # deletes the routes (IPv4 without a notification), carrier loss
            # flushes the RMAC neighbors, and detaching the VXLAN port
            # flushes its FDB. zebra-rs must put all of it back.
            def type5_restored(name):
                for prefix in ['10.20.1.0/24', '2001:db8:20:1::/64']:
                    expect(f'{name}: Type-5 {prefix}', lambda prefix=prefix:
                           any(r.get('dev') == 'br2000' and r.get('protocol') == 'bgp'
                               for r in route('v2', prefix)))
                for af, gateway in rmac_gateways(1):
                    expect(f'{name}: RMAC neighbor {af}', lambda af=af, gateway=gateway:
                           'extern_learn' in ns('v2', 'ip', af, 'neighbor', 'show',
                                               gateway, 'dev', 'br2000').stdout)
                expect(f'{name}: RMAC FDB', lambda:
                       f'dst {vtep(1)}' in ns('v2', 'bridge', 'fdb', 'show', 'dev', 'vx2000').stdout)
                for af, address in [('-4', '10.20.1.10'), ('-6', '2001:db8:20:1::10')]:
                    expect(f'{name}: routed {af}', lambda af=af, address=address:
                           ns('r2', 'ping', af, '-c', '1', '-W', '1', address,
                              check=False).returncode == 0)

            ns('v2', 'ip', 'link', 'set', 'br2000', 'down')
            expect('Bridge admin-down removes the IPv4 Type-5 route', lambda:
                   not route('v2', '10.20.1.0/24'))
            ns('v2', 'ip', 'link', 'set', 'br2000', 'up')
            type5_restored('Bridge admin flap')

            # The flushed neighbors are put back as soon as the deletion is
            # seen, so the gap itself is too short to assert on.
            ns('v2', 'ip', 'link', 'set', 'vx2000', 'down')
            time.sleep(1)
            ns('v2', 'ip', 'link', 'set', 'vx2000', 'up')
            type5_restored('VXLAN carrier flap')

            ns('v2', 'ip', 'neighbor', 'flush', 'dev', 'br2000')
            ns('v2', 'ip', '-6', 'neighbor', 'flush', 'dev', 'br2000')
            ns('v2', 'bridge', 'fdb', 'del', '02:00:00:00:02:01', 'dev', 'vx2000', 'master')
            ns('v2', 'bridge', 'fdb', 'del', '02:00:00:00:02:01', 'dev', 'vx2000', 'self',
               check=False)
            type5_restored('Neighbor and FDB flush')

            ns('v2', 'ip', 'link', 'set', 'vx2000', 'nomaster')
            ns('v2', 'ip', 'link', 'set', 'vx2000', 'master', 'br2000')
            type5_restored('VXLAN re-attach')

            # A route removed by someone else comes back (FRR does the same
            # for its own routes).
            ns('v2', 'ip', 'route', 'del', '10.20.1.0/24', 'table', '100')
            ns('v2', 'ip', '-6', 'route', 'del', '2001:db8:20:1::/64', 'table', '100')
            type5_restored('External route delete')

            # Moving the L3-VNI VXLAN to another bridge moves its state and
            # leaves no RMAC neighbors on the old bridge. Then move it back.
            ns('v2', 'ip', 'link', 'add', 'br2000b', 'type', 'bridge')
            ns('v2', 'ip', 'link', 'set', 'br2000b', 'address', '02:00:00:00:02:02')
            ns('v2', 'ip', 'link', 'set', 'br2000b', 'master', 'tenant100')
            ns('v2', 'ip', 'link', 'set', 'br2000b', 'up')
            # A dummy port keeps each bridge's carrier up when the VXLAN
            # leaves; otherwise the kernel flushes its neighbors itself and
            # the "none left" checks prove nothing.
            for bridge in ['br2000', 'br2000b']:
                ns('v2', 'ip', 'link', 'add', 'd' + bridge, 'type', 'dummy')
                ns('v2', 'ip', 'link', 'set', 'd' + bridge, 'master', bridge)
                ns('v2', 'ip', 'link', 'set', 'd' + bridge, 'up')
            for new, old in [('br2000b', 'br2000'), ('br2000', 'br2000b')]:
                ns('v2', 'ip', 'link', 'set', 'vx2000', 'master', new)
                for prefix in ['10.20.1.0/24', '2001:db8:20:1::/64']:
                    expect(f'Move to {new}: Type-5 {prefix}', lambda prefix=prefix, new=new:
                           any(r.get('dev') == new and r.get('protocol') == 'bgp'
                               for r in route('v2', prefix)))
                for af, gateway in rmac_gateways(1):
                    expect(f'Move to {new}: RMAC neighbor {af}', lambda af=af, gateway=gateway, new=new:
                           'extern_learn' in ns('v2', 'ip', af, 'neighbor', 'show',
                                               gateway, 'dev', new).stdout)
                    expect(f'Move to {new}: none left on {old} {af}', lambda af=af, gateway=gateway, old=old:
                           not ns('v2', 'ip', af, 'neighbor', 'show', gateway, 'dev', old).stdout)
                for af, address in [('-4', '10.20.1.10'), ('-6', '2001:db8:20:1::10')]:
                    expect(f'Move to {new}: routed {af}', lambda af=af, address=address:
                           ns('r2', 'ping', af, '-c', '1', '-W', '1', address,
                              check=False).returncode == 0)
            for link in ['dbr2000', 'dbr2000b', 'br2000b']:
                ns('v2', 'ip', 'link', 'del', link)

            # MAC mobility (RFC 7432 §7.7): l1's station moves behind v2 and
            # back. Each side must end with the station local where it is and
            # remote (toward the other VTEP) where it is not, and stay so:
            # a route the station's new PE outranks must not be reinstalled
            # when the old PE withdraws its MAC and MAC/IP routes one by one.
            station, station_ip = '02:00:00:10:00:01', '10.10.0.101'

            def fdb(v):
                return [line for line in ns(v, 'bridge', 'fdb', 'show', 'br', 'br1000').stdout.splitlines()
                        if line.startswith(station)]

            def local_on(v):
                rows = fdb(v)
                return any(' dev access ' in r for r in rows) and not any(' dev vx1000 ' in r and 'master' in r for r in rows)

            def remote_on(v, peer):
                return any(' dev vx1000 ' in r and f'dst {vtep(peer)}' in r for r in fdb(v))

            def settle(name, check, seconds=8):
                expect(name, check)
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    if not check():
                        checks.append({'name': name + ' (stable)', 'passed': False})
                        raise RuntimeError('unstable: ' + name)
                    time.sleep(0.5)
                checks.append({'name': name + ' (stable)', 'passed': True})
                print('PASS:', name, '(stable)', flush=True)

            l2_mac = ns('l2', 'cat', '/sys/class/net/eth0/address').stdout.strip()
            ns('l1', 'ip', 'link', 'set', 'eth0', 'down')
            ns('l2', 'ip', 'link', 'set', 'eth0', 'address', station)
            ns('l2', 'ip', 'address', 'add', station_ip + '/24', 'dev', 'eth0')
            ns('l2', 'ping', '-c', '2', '-W', '1', '-I', station_ip, '10.10.0.2', check=False)
            settle('Mobility: station local on v2', lambda: local_on('v2'))
            settle('Mobility: station remote on v1', lambda: remote_on('v1', 2))
            # Back to l1.
            ns('l2', 'ip', 'address', 'del', station_ip + '/24', 'dev', 'eth0')
            ns('l2', 'ip', 'link', 'set', 'eth0', 'address', l2_mac)
            ns('l1', 'ip', 'link', 'set', 'eth0', 'up')
            ns('l1', 'ping', '-c', '2', '-W', '1', '10.10.0.1', check=False)
            settle('Mobility back: station local on v1', lambda: local_on('v1'), seconds=12)
            settle('Mobility back: station remote on v2', lambda: remote_on('v2', 1))
            expect('Mobility back: l2 reaches the station', lambda:
                   ns('l2', 'ping', '-c', '1', '-W', '1', station_ip, check=False).returncode == 0)

            # Duplicate address detection (RFC 7432 §15.1): one MAC/IP behind
            # both access ports, alternately talking. With max-moves 3 the
            # third move v2 sees (learn, takeover, learn) freezes the address
            # there: v2 stops advertising it and installs nothing for it, so
            # the flapping stops with the station local on both sides. A
            # clear releases it: v2 advertises again, outranking v1's route.
            dup_mac, dup_ip = '02:00:00:10:00:aa', '10.10.0.201'
            for v in ['v1', 'v2']:
                ns(v, str(args.vtyctl), 'apply', '-c',
                   'set router bgp afi-safi evpn dup-addr-detection max-moves 3\n'
                   'set router bgp afi-safi evpn dup-addr-detection freeze permanent')
            for l in ['l1', 'l2']:
                ns(l, 'ip', 'link', 'add', 'dup', 'link', 'eth0', 'type', 'macvlan', 'mode', 'bridge')
                ns(l, 'ip', 'link', 'set', 'dup', 'address', dup_mac)
                ns(l, 'ip', 'address', 'add', dup_ip + '/24', 'dev', 'dup')

            def dup_fdb(v):
                return [line for line in ns(v, 'bridge', 'fdb', 'show', 'br', 'br1000').stdout.splitlines()
                        if line.startswith(dup_mac)]

            def dup_local(v):
                # The forwarding row: a non-VLAN-filtering bridge looks up
                # VLAN 0, and a frozen address keeps any `vlan 1` row an
                # earlier remote install left.
                rows = [r for r in dup_fdb(v) if ' vlan ' not in r]
                return any(' dev access ' in r for r in rows) and not any(' dev vx1000 ' in r and 'master' in r for r in rows)

            def dup_remote(v, peer):
                return any(' dev vx1000 ' in r and f'dst {vtep(peer)}' in r for r in dup_fdb(v))

            def duplicates(v):
                view = json.loads(ns(v, str(args.vtyctl), 'show', '-j', 'show evpn dup-addr').stdout)
                return [a for a in view['addresses'] if a['mac'] == dup_mac and a['duplicate']]

            def talk(l, v):
                ns(l, 'ip', 'link', 'set', 'dup', 'up')
                ns(l, 'ping', '-c', '1', '-W', '1', '-I', 'dup', f'10.10.0.{v}', check=False)
                ns(l, 'ip', 'link', 'set', 'dup', 'down')

            talk('l1', 1)
            expect('DAD: v1 learns the address', lambda: dup_local('v1') and dup_remote('v2', 1))
            talk('l2', 2)  # v2: move 1
            expect('DAD: v2 takes it over', lambda: dup_local('v2') and dup_remote('v1', 2))
            talk('l1', 1)  # v2: move 2 (takeover)
            expect('DAD: v1 takes it back', lambda: dup_local('v1') and dup_remote('v2', 1))
            talk('l2', 2)  # v2: move 3, frozen
            expect('DAD: v2 detects the duplicate', lambda: duplicates('v2'))
            settle('DAD: frozen local on v2, local on v1', lambda: dup_local('v2') and dup_local('v1'))
            expect('DAD: v1 has detected nothing', lambda: not duplicates('v1'))
            ns('v2', str(args.vtyctl), 'clear', 'clear bgp evpn dup-addr vni all')
            expect('DAD: clear releases v2', lambda: not duplicates('v2'))
            settle('DAD: after clear, v1 points at v2', lambda: dup_remote('v1', 2) and dup_local('v2'))
            for l in ['l1', 'l2']:
                ns(l, 'ip', 'link', 'del', 'dup')
            for v in ['v1', 'v2']:
                ns(v, str(args.vtyctl), 'apply', '-c',
                   'delete router bgp afi-safi evpn dup-addr-detection max-moves\n'
                   'delete router bgp afi-safi evpn dup-addr-detection freeze')

            # A crash leaves routes behind. On restart, each owner's route
            # replaces its leftover; the rest are swept after the grace
            # period; operator routes stay; a pre-RTPROT_ZEBRA static is
            # adopted by the same configured static.
            def protocols(node, prefix):
                return [r.get('protocol') for r in main_route(node, prefix)]
            def priorities(prefix):
                return sorted(r.get('metric', 0) for r in main_route('v2', prefix))
            removed_floating = ['10.99.3.0/24', '2001:db8:99:3::/64']
            changed_floating = ['10.99.4.0/24', '2001:db8:99:4::/64']
            for prefix in removed_floating + changed_floating:
                expect(f'Floating static {prefix} installs both priorities', lambda prefix=prefix:
                       priorities(prefix) == [100, 200])
            for prefix in ['10.99.1.0/24', '10.99.2.0/24', '2001:db8:99:1::/64']:
                expect(f'Static {prefix} installs as proto zebra', lambda prefix=prefix:
                       protocols('v2', prefix) == ['zebra'])
            expect('v2 Type-5 10.31.1.0/24', lambda:
                   any(r.get('dev') == 'br2000' for r in route('v2', '10.31.1.0/24')))
            processes[1].kill()
            processes[1].wait()
            ns('v1', 'ip', 'route', 'del', 'blackhole', '10.31.1.0/24', 'table', '100', 'proto', 'static')
            ns('v2', 'ip', 'route', 'add', 'blackhole', '10.97.0.0/24', 'proto', 'static')
            removed = ['10.99.2.0/24', *removed_floating]
            restart = [line.replace('metric 200', 'metric 300')
                       if any(prefix in line for prefix in changed_floating) else line
                       for line in configs['v2'] if not any(prefix in line for prefix in removed)]
            restart.append('set router static ipv4 route 10.97.0.0/24 nexthop blackhole')
            config = Path(directory) / 'v2-restart.conf'
            config.write_text('\n'.join(restart) + '\n')
            processes[1] = start('v2', config, logs[1][1], '--leftover-sweep-time', '8')
            expect('Restart: v2 EVPN established', lambda: 'Estab' in show('v2', 'show bgp summary'))
            type5_restored('Restart')
            expect('Restart: unreplaced static leftover swept', lambda:
                   not main_route('v2', '10.99.2.0/24'), timeout=45)
            expect('Restart: VRF BGP leftover swept', lambda:
                   not route('v2', '10.31.1.0/24'), timeout=45)
            for prefix in removed_floating:
                expect(f'Restart: every floating leftover priority swept {prefix}', lambda prefix=prefix:
                       not main_route('v2', prefix), timeout=45)
            for prefix in changed_floating:
                expect(f'Restart: floating backup replaced {prefix}', lambda prefix=prefix:
                       priorities(prefix) == [100, 300])
            for prefix in ['10.99.1.0/24', '2001:db8:99:1::/64']:
                expect(f'Restart: configured static {prefix} kept', lambda prefix=prefix:
                       protocols('v2', prefix) == ['zebra'])
            expect('Restart: operator proto static kept', lambda:
                   protocols('v2', '10.98.0.0/24') == ['static'])
            expect('Restart: legacy proto static adopted', lambda:
                   protocols('v2', '10.97.0.0/24') == ['zebra'])

            # Removing one NLRI must retain the other bindings and their MAC.
            # l1 first refreshes its neighbors on v1, which may have aged
            # out during the scenarios above. The mobility scenario's link
            # flap removed l1's IPv6 address (keep_addr_on_down is off).
            ns('l1', 'ip', '-6', 'address', 'replace', '2001:db8:10::101/64', 'dev', 'eth0', 'nodad')
            ns('l1', 'ping', '-c', '1', '-W', '1', '10.10.0.1', check=False)
            ns('l1', 'ping', '-6', '-c', '1', '-W', '1', '2001:db8:10::1', check=False)
            expect('Type-2 IPv6 binding before IPv4 withdrawal', lambda:
                   'extern_learn' in ns('v2', 'ip', '-6', 'neighbor', 'show', '2001:db8:10::101', 'dev', 'br1000').stdout)
            ns('v1', 'ip', '-4', 'neighbor', 'del', '10.10.0.101', 'dev', 'br1000')
            expect('Type-2 IPv4 withdrawal', lambda:
                   not ns('v2', 'ip', '-4', 'neighbor', 'show', '10.10.0.101', 'dev', 'br1000').stdout)
            expect('Type-2 IPv6 survives IPv4 withdrawal', lambda:
                   'extern_learn' in ns('v2', 'ip', '-6', 'neighbor', 'show', '2001:db8:10::101', 'dev', 'br1000').stdout)
            expect('Type-2 MAC survives IPv4 withdrawal', lambda:
                   '02:00:00:10:00:01' in ns('v2', 'bridge', 'fdb', 'show', 'dev', 'vx1000').stdout)
            ns('v1', 'ip', 'route', 'del', 'blackhole', '10.30.1.0/24', 'table', '100', 'proto', 'static')
            expect('Static blackhole Type-5 withdrawal', lambda: not route('v2', '10.30.1.0/24'))
            expect('Other Type-5 retains RMAC adjacency', lambda:
                   ns('r2', 'ping', '-c', '1', '-W', '1', '10.20.1.10', check=False).returncode == 0)
            for af, prefix in [('ipv4', '10.20.1.0/24'), ('ipv6', '2001:db8:20:1::/64')]:
                ns('v1', str(args.vtyctl), 'apply', '-c',
                   f'delete router bgp vrf tenant100 afi-safi {af} network {prefix}')
                expect(f'Type-5 withdrawal {prefix}', lambda prefix=prefix: not route('v2', prefix))
            ns('v1', 'ip', '-6', 'route', 'del', 'blackhole', '2001:db8:30:1::/64',
               'table', '100', 'proto', 'static')
            expect('Final Type-5 withdrawal', lambda: not route('v2', '2001:db8:30:1::/64'))
            for af, gateway in rmac_gateways(1):
                expect(f'Unused RMAC neighbor cleanup {af}', lambda af=af, gateway=gateway:
                       not ns('v2', 'ip', af, 'neighbor', 'show', gateway, 'dev', 'br2000').stdout)
            report['passed'] = True
    except Exception as exc:
        report['passed'] = False
        report['error'] = str(exc)
        # Keep diagnostic snapshots before cleanup.
        report['diagnostics'] = {}
        for v in ['v1', 'v2']:
            if tag + '-' + v in namespaces:
                report['diagnostics'][v] = {
                    'routes': ns(v, 'ip', '-j', 'route', 'show', 'table', 'all', check=False).stdout,
                    'routes6': ns(v, 'ip', '-6', '-j', 'route', 'show', 'table', 'all', check=False).stdout,
                    'neighbors': ns(v, 'ip', 'neighbor', 'show', check=False).stdout,
                    'fdb': ns(v, 'bridge', 'fdb', 'show', check=False).stdout,
                    'evpn': ns(v, str(args.vtyctl), 'show', 'show bgp evpn', check=False).stdout}
        raise
    finally:
        for process in processes:
            process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        # Namespace deletion does not kill its processes; stop daemons first.
        for namespace in reversed(namespaces):
            run('ip', 'netns', 'delete', namespace, check=False)
        if not report.get('passed', False):
            report['logs'] = {}
            for node, log in logs:
                log.seek(0)
                report['logs'][node] = log.read()[-12000:]
        for _, log in logs:
            log.close()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(f'{sum(c["passed"] for c in checks)}/{len(checks)} checks; report: {args.output}', flush=True)


if __name__ == '__main__':
    main()
