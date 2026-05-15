# RustCrypto: SHA-3

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Implementation of the [SHA-3] family of cryptographic hash algorithms.

There are 4 standard fixed-size algorithms specified in the SHA-3 standard:
`SHA3-224`, `SHA3-256`, `SHA3-384`, `SHA3-512`.

`SHAKE128` and `SHAKE256` extendable output functions (XOF) are defined in the [`shake`] crate

Additionally, this crate supports:
- `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512`: NIST submission without padding changes
- `Keccak256Full`: CryptoNight variant of SHA-3

## Examples

Output size of SHA3-256 is fixed, so its functionality is usually
accessed via the `Digest` trait:

```rust
use hex_literal::hex;
use sha3::{Digest, Sha3_256};

let mut hasher = Sha3_256::new();
hasher.update(b"abc");
let hash = hasher.finalize();

assert_eq!(hash, hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"));
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

[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[`shake`]: http://docs.rs/shake
[`digest`]: https://docs.rs/digest
