# RustCrypto: SHA-3

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Implementation of the [TurboSHAKE] family of fast and secure extendable-output functions (XOFs).

## Examples

SHAKE functions have an extendable output, so finalization method returns
XOF reader from which results of arbitrary length can be read. Note that
these functions do not implement `Digest`, so lower-level traits have to
be imported:

```rust,ignore
// TODO: update to TurboSHAKE
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use hex_literal::hex;

let mut hasher = Shake128::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("5881092dd818bf5cf8a3"));
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

[crate-image]: https://img.shields.io/crates/v/sha3.svg
[crate-link]: https://crates.io/crates/sha3
[docs-image]: https://docs.rs/sha3/badge.svg
[docs-link]: https://docs.rs/sha3/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/sha3.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/sha3.yml?query=branch:master

[//]: # (general links)

[TurboSHAKE]: https://keccak.team/turboshake.html
[`digest`]: https://docs.rs/digest
