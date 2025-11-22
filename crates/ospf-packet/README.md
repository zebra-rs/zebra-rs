# OSPFv2 and OSPFv3 Parser and Emitter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)

A parser and an emitter for [OSPFv2] and [OSPFv3]. This library is inspired by
[ospf-parser], which provides a pure Rust parser for OSPF using the [nom] parser
combinator. Building upon [ospf-parser], this library adds an emitter to encode
OSPFv2 and OSPFv3 packets into a byte stream.

[OSPFv2]: https://tools.ietf.org/html/rfc2328 "OSPF Version 2, RFC 2328"
[OSPFv3]: https://tools.ietf.org/html/rfc5340 "OSPF for IPv6, RFC 5340"
[ospf-parser]: https://github.com/rusticata/ospf-parser "OSPFv2 and OSPFv3 Parser"
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
