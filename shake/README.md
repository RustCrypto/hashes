# RustCrypto: SHAKE

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]


Implementation of the SHAKE family of extendable-output functions (XOFs)
defined in [NIST FIPS 202].

## Examples

SHAKE functions have an extendable output, so finalization methods return
XOF reader from which results of arbitrary length can be read.

```rust
use shake::Shake128;
use shake::digest::{Update, ExtendableOutput, XofReader};
use hex_literal::hex;

let mut hasher = Shake128::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("5881092dd818bf5cf8a3"));
reader.read(&mut buf);
assert_eq!(buf, hex!("ddb793fbcba74097d5c5"));
```

See the [`digest`] crate docs for additional examples.

## License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/shake.svg
[crate-link]: https://crates.io/crates/shake
[docs-image]: https://docs.rs/shake/badge.svg
[docs-link]: https://docs.rs/shake
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/shake.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/shake.yml?query=branch:master

[//]: # (general links)

[NIST FIPS 202]: https://csrc.nist.gov/pubs/fips/202/final
[`digest`]: https://docs.rs/digest
