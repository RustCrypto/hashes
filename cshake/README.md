# RustCrypto: cSHAKE

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Implementation of the cSHAKE family of extendable-output functions (XOFs)
defined in the NIST [SHA-3 Derived Functions].

## Examples

cSHAKE functions have an extendable output, so finalization methods return
XOF reader from which results of arbitrary length can be read.

```rust
use cshake::CShake128;
use cshake::digest::{CustomizedInit, Update, ExtendableOutput, XofReader};
use hex_literal::hex;

let mut hasher = CShake128::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("5881092dd818bf5cf8a3"));
reader.read(&mut buf);
assert_eq!(buf, hex!("ddb793fbcba74097d5c5"));

// With customization string
let mut hasher = CShake128::new_customized(b"my customization string");
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("a296533c8d5753bf3421"));
reader.read(&mut buf);
assert_eq!(buf, hex!("124e8eb79262233170ce"));
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

[crate-image]: https://img.shields.io/crates/v/cshake.svg
[crate-link]: https://crates.io/crates/cshake
[docs-image]: https://docs.rs/cshake/badge.svg
[docs-link]: https://docs.rs/cshake
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/cshake.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/cshake.yml?query=branch:master

[//]: # (general links)

[SHA-3 Derived Functions]: https://csrc.nist.gov/pubs/sp/800/185/final
[`digest`]: https://docs.rs/digest
