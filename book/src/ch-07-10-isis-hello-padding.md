# IS-IS Hello Padding and MTU

IS-IS Hello PDUs are padded to the full interface MTU so that an
adjacency only forms when the link really carries maximum-size PDUs in
both directions (the ISO 10589 MTU probe). A link that silently eats
large frames is far worse discovered later — as black-holed LSPs or
data traffic — than as an adjacency that refuses to come up.

This chapter pins down exactly what lands on the wire, the vendor
interop trap that follows from it, and the two escape hatches:
`hello padding-size` and `hello padding disable`.

## What a padded Hello looks like on the wire

The padder fills the IIH PDU to `MTU − 3`, the send path prepends the
3-byte LLC header (`FE FE 03`), and the kernel adds the 14-byte
Ethernet header. With a 4096-byte interface MTU:

```
Ethernet Header                  14
Ethernet Payload (4093 + 3) =  4096
  IIH PDU        = 4093
  LLC header     =    3
                        14 + 4096 = 4110
```

A packet capture therefore shows **MTU + 14** byte Hello frames — 4110
for MTU 4096, 1514 for MTU 1500. This is correct under Linux/IETF MTU
semantics (MTU = maximum L2 payload, Ethernet header excluded) and is
byte-identical to FRR and Cisco IOS behaviour. The interface MTU is
read from the kernel via netlink; there is no separate zebra-rs MTU
configuration.

## The interop trap: peers that count MTU differently

Some platforms configure MTU in *media MTU* terms — the number includes
the 14-byte Ethernet header, and on some platforms the 4-byte FCS as
well. Such a peer configured with "MTU 4096" pads its own Hellos 18
bytes smaller (4092-byte frames in a capture) **and drops our
4110-byte frames on ingress as giants**.

The symptom pattern is distinctive:

- pings and ordinary traffic cross the link fine (small frames);
- both sides send Hellos, but each side's padded Hello never arrives
  at the other, or arrives in only one direction;
- the adjacency sits in Down/Init forever with nothing logged — the
  drop happens in the receiving interface, below IS-IS.

The clean fix is to make both sides agree on the payload size: raise
the media-MTU peer's number by 18 (4096 → 4114), or lower the
zebra-rs-side kernel MTU by 18 (4096 → 4078). When neither number can
be changed, use `padding-size`.

## Padding to an explicit frame length — `hello padding-size`

```
set router isis interface eth0 hello padding-size 4092
```

| YANG leaf | Default | Range | Units |
|---|---|---|---|
| `/router/isis/interface/<n>/hello/padding-size` | unset (interface MTU) | 64..16384 | bytes |

`padding-size` pads Hellos toward an explicit target instead of the
interface MTU. The value is the **on-wire Ethernet frame length as
read from a packet capture** — 14-byte header + LLC + PDU, FCS
excluded — because that is the one number both ends of an MTU-semantics
dispute can see and agree on: `padding-size 4092` against a
media-MTU-4096 peer emits exactly the 4092-byte frames the peer itself
sends, and the MTU probe still runs, just at the length both sides
accept.

Semantics worth knowing:

- The 14-byte Ethernet header is subtracted internally; the result is
  clamped to the interface MTU (the kernel rejects payloads above it),
  so an over-large value degrades to plain full-MTU padding.
- The padder never truncates a Hello. A value smaller than the
  unpadded Hello simply means no padding is added.
- Ignored while `hello padding disable` is set.
- Runtime `set`/`delete` re-originates Hellos immediately — no
  restart, no adjacency flap needed for the new size to take effect.

`show isis interface detail` confirms what is on the wire:

```
    Hello interval: 3, Holddown count: 10, Padding: yes (size 4092)
```

The blunter alternative, `hello padding disable`, skips the probe
entirely (see [Timer Configuration](ch-07-01-isis-timers.md)); the
adjacency then forms across the mismatch, which is acceptable while
`lsp-mtu` (default 1497) stays below both sides' real capacity.

## Debugging with tcpdump

One capture pitfall: libpcap's `isis` filter primitive **misses**
padded Hellos on links with MTU above ~1500. The 802.3 length field
carries the payload length (zebra-rs and FRR both send it that way),
and values above 1536 make libpcap classify the frame as an unknown
EtherType, so `tcpdump isis` shows the small PDUs but not the padded
IIHs — exactly the frames under investigation. Match the LLC and ISO
discriminator bytes by offset instead:

```
tcpdump -i eth0 'ether[14:2] = 0xfefe and ether[16] = 3 and ether[17] = 0x83'
```

## BDD coverage

The `isis_hello_padding_mtu` feature proves the whole story end to
end: matched MTUs pad to exactly MTU + 14 and the adjacency forms; a
receiver with a smaller MTU silently drops the padded Hellos while
pings still pass; `padding-size` shrinks the frames to a length the
peer accepts and the adjacency recovers; deleting it restores full-MTU
probing; and `padding disable` skips the probe entirely.
