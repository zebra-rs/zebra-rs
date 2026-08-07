#!/usr/bin/env python3
"""Scripted BGP listener that fails the DUT's first connection *in OpenSent*.

Regression harness for the OpenSent redial pacer. `fsm_conn_fail`'s
OpenSent arm used to restart the full ConnectRetryTimer (120s by default,
30s now) instead of the short idle-hold pacer its Connect-state sibling
`fsm_dial_fail` uses, so a peer whose TCP died after it had sent its OPEN
sat in Active for up to two minutes before redialling.

Reproducing that state router-to-router is not deterministic — it needs a
connection to die in the window between "TCP is up, OPEN sent" and "peer's
OPEN received", which in the wild is a §6.8 collision. This script makes it
deterministic:

  connection 1  accept, wait for the DUT's OPEN so it is provably in
                OpenSent, then abort with RST (SO_LINGER 0). The DUT takes
                TcpConnectionFails *in OpenSent* — the arm under test.
  connection 2+ behave as a real speaker: OPEN, then KEEPALIVE, and keep
                answering, so the session establishes.

So the time from the reset to Established is exactly the redial pacer.
With the idle-hold pacer that is ~5s; with the ConnectRetryTimer it is 30s
(or 120s before the default changed). The feature asserts Established
inside a window between the two — see bgp_opensent_redial.feature, where
the *fixed wait is the assertion* and must not be turned into a polling
step.

The DUT dials us, so this script listens on 179 and the neighbor needs no
passive-mode (unlike bgp_mp_reach_send.py, which connects out).

Usage: bgp_opensent_reset.py <local-as> <router-id> [listen-addr] [state-file]
"""

import os
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
MSG_OPEN, MSG_UPDATE, MSG_NOTIFICATION, MSG_KEEPALIVE = 1, 2, 3, 4
CAP_MP, CAP_AS4 = 1, 65
AFI_IP, SAFI_UNICAST = 1, 1
HOLDTIME = 90


def bgp_msg(msg_type, body):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def open_msg(local_as, router_id):
    caps = bytes([CAP_MP, 4]) + struct.pack("!HBB", AFI_IP, 0, SAFI_UNICAST)
    caps += bytes([CAP_AS4, 4]) + struct.pack("!I", local_as)
    opt = bytes([2, len(caps)]) + caps
    my_as2 = local_as if local_as < 65536 else 23456  # AS_TRANS
    body = struct.pack(
        "!BHH4sB", 4, my_as2, HOLDTIME, socket.inet_aton(router_id), len(opt)
    ) + opt
    return bgp_msg(MSG_OPEN, body)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_msg(sock):
    hdr = recv_exact(sock, 19)
    if hdr is None:
        return None
    length, msg_type = struct.unpack("!HB", hdr[16:19])
    body = recv_exact(sock, length - 19) if length > 19 else b""
    if length > 19 and body is None:
        return None
    return msg_type, body


def note(state_file, text):
    """Append a progress line the feature (or a human) can read."""
    print(text, flush=True)
    if state_file:
        with open(state_file, "a") as fh:
            fh.write("%.3f %s\n" % (time.time(), text))


def abort_connection(conn):
    """Close with RST rather than FIN.

    A graceful FIN is also a TcpConnectionFails for the DUT, but RST
    removes any doubt about half-open lingering and gets the event to the
    FSM immediately.
    """
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


def serve_session(conn, local_as, router_id, state_file):
    """Full speaker: OPEN, KEEPALIVE, then answer keepalives forever."""
    conn.sendall(open_msg(local_as, router_id))
    conn.sendall(bgp_msg(MSG_KEEPALIVE, b""))
    conn.settimeout(HOLDTIME)
    while True:
        msg = read_msg(conn)
        if msg is None:
            note(state_file, "peer closed the established connection")
            return
        msg_type, _body = msg
        if msg_type == MSG_OPEN:
            conn.sendall(bgp_msg(MSG_KEEPALIVE, b""))
        elif msg_type == MSG_KEEPALIVE:
            conn.sendall(bgp_msg(MSG_KEEPALIVE, b""))
        elif msg_type == MSG_NOTIFICATION:
            note(state_file, "peer sent NOTIFICATION; connection over")
            return


def main():
    local_as = int(sys.argv[1])
    router_id = sys.argv[2]
    listen_addr = sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0"
    state_file = sys.argv[4] if len(sys.argv) > 4 else None
    if state_file and os.path.exists(state_file):
        os.remove(state_file)

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((listen_addr, 179))
    lsock.listen(5)
    note(state_file, "listening on %s:179" % listen_addr)

    first = True
    while True:
        conn, peer = lsock.accept()
        if first:
            # Wait for the DUT's OPEN before resetting: that is the proof
            # it has left Connect and is sitting in OpenSent, which is the
            # state whose failure arm this exercises. Without this wait the
            # reset could land while it is still in Connect and take the
            # already-correct `fsm_dial_fail` path instead — the test would
            # then pass no matter what OpenSent does.
            conn.settimeout(30)
            try:
                msg = read_msg(conn)
            except socket.timeout:
                msg = None
            if msg is not None and msg[0] == MSG_OPEN:
                note(state_file, "reset-in-opensent %s" % (peer,))
            else:
                note(state_file, "no OPEN before reset (got %r) from %s" % (msg, peer))
            abort_connection(conn)
            first = False
            continue
        note(state_file, "accepting-session %s" % (peer,))
        try:
            serve_session(conn, local_as, router_id, state_file)
        except (OSError, socket.timeout) as exc:
            note(state_file, "session ended: %s" % exc)
        finally:
            conn.close()
        # Exit once the served session ends rather than looping back to
        # accept(). The feature only needs one session, and a listener
        # that outlives its scenario keeps port 179 in a namespace that
        # is about to be deleted — the next run's instance then dies on
        # bind *after* clearing the state file, which reads as "the
        # reset never happened". Deleting a namespace does not kill the
        # processes inside it, so self-terminating is the reliable fix.
        note(state_file, "listener exiting")
        return


if __name__ == "__main__":
    main()
