#!/usr/bin/env python3
"""Exercise EVPN using only Linux namespaces and two zebra-rs speakers."""
import argparse
import hashlib
import json
import os
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
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo; this creates and removes isolated network namespaces')
    tag = 'ek' + uuid.uuid4().hex[:6]
    namespaces = []
    processes = []
    logs = []
    checks = []
    report = {'binary_sha256': hashlib.sha256(args.zebra.read_bytes()).hexdigest(),
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
                ns(v, 'ip', 'address', 'add', f'198.51.100.{i}/32', 'dev', 'lo')
                ns(v, 'ip', 'route', 'add', f'198.51.100.{3-i}/32',
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
                       'local', f'198.51.100.{i}', 'dstport', '4789', 'nolearning')
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
                       f'dst 198.51.100.{peer}' in ns(v, 'bridge', 'fdb', 'show', 'dev', 'vx1000').stdout)
                expect(f'{v} Type-3 IMET', lambda v=v, peer=peer:
                       f'[3]:[0]:[32]:[198.51.100.{peer}]' in show(v, 'show bgp evpn'))
                expect(f'{v} mapped IPv6 RMAC adjacency', lambda v=v, peer=peer:
                       'extern_learn' in ns(v, 'ip', '-6', 'neighbor', 'show',
                                           f'::ffff:198.51.100.{peer}', 'dev', 'br2000').stdout)
                for prefix in [f'10.20.{peer}.0/24', f'2001:db8:20:{peer}::/64',
                               f'10.30.{peer}.0/24', f'2001:db8:30:{peer}::/64']:
                    expect(f'{v} Type-5 {prefix}', lambda v=v, prefix=prefix:
                           any(r.get('dev') == 'br2000' and r.get('protocol') == 'bgp' for r in route(v, prefix)))
                for af, address in [('-4', f'10.20.{peer}.10'), ('-6', f'2001:db8:20:{peer}::10')]:
                    expect(f'r{i} routed {af}', lambda i=i, af=af, address=address:
                           ns('r'+str(i), 'ping', af, '-c', '1', '-W', '1', address, check=False).returncode == 0)

            # The kernel drops bridge Type-5 state on its own: admin-down
            # deletes the routes (IPv4 without a notification), carrier loss
            # flushes the RMAC neighbors, and detaching the VXLAN port
            # flushes its FDB. zebra-rs must put all of it back.
            def type5_restored(name):
                for prefix in ['10.20.1.0/24', '2001:db8:20:1::/64']:
                    expect(f'{name}: Type-5 {prefix}', lambda prefix=prefix:
                           any(r.get('dev') == 'br2000' and r.get('protocol') == 'bgp'
                               for r in route('v2', prefix)))
                for af, gateway in [('-4', '198.51.100.1'), ('-6', '::ffff:198.51.100.1')]:
                    expect(f'{name}: RMAC neighbor {af}', lambda af=af, gateway=gateway:
                           'extern_learn' in ns('v2', 'ip', af, 'neighbor', 'show',
                                               gateway, 'dev', 'br2000').stdout)
                expect(f'{name}: RMAC FDB', lambda:
                       'dst 198.51.100.1' in ns('v2', 'bridge', 'fdb', 'show', 'dev', 'vx2000').stdout)
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
                for af, gateway in [('-4', '198.51.100.1'), ('-6', '::ffff:198.51.100.1')]:
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
            for af, gateway in [('-4', '198.51.100.1'), ('-6', '::ffff:198.51.100.1')]:
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
