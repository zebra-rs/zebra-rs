# OSPFv2 and OSPFv3 Parser and Emitter

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](../../LICENSE-AGPL)

A parser and an emitter for [OSPFv2] and [OSPFv3]. This is a pure Rust parser
for OSPF built on the [nom] parser combinator, with an emitter to encode OSPFv2
and OSPFv3 packets into a byte stream.

[OSPFv2]: https://tools.ietf.org/html/rfc2328 "OSPF Version 2, RFC 2328"
[OSPFv3]: https://tools.ietf.org/html/rfc5340 "OSPF for IPv6, RFC 5340"
[nom]: https://github.com/rust-bakery/nom "nom parser combinator"

## Example

Please make it sure to include library in `Cargo.toml`.

``` toml
[dependencies]
ospf-packet = "0.5"
```

Then, you can try to parse the byte stream.

``` rust
use ospf-packet;

fn test() {
    match ospf-packet::parse(input) {
       Ok(packet) => {
           println!("Packet: {}", packet);
       }
       Err(err) => {
           println!("Error: {}", err);
       }
    }
}
```

## License

Licensed under the GNU Affero General Public License v3.0 or later
(AGPL-3.0-or-later). See [LICENSE-AGPL](../../LICENSE-AGPL).
