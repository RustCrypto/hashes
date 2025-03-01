# RustCrypto: SHA-3

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SHA-3] cryptographic hash algorithms.

There are 6 standard algorithms specified in the SHA-3 standard:

* `SHA3-224`
* `SHA3-256`
* `SHA3-384`
* `SHA3-512`
* `SHAKE128`, an extendable output function (XOF)
* `SHAKE256`, an extendable output function (XOF)
* `Keccak224`, `Keccak256`, `Keccak384`, `Keccak512` (NIST submission
   without padding changes)

This crates supports `cSHAKE128` and `cSHAKE256`, the customizable XOFs as defined in the NIST [SHA-3 Derived Functions].

This crates additionally supports the `TurboSHAKE` XOF variant.

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

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
```

SHAKE functions have an extendable output, so finalization method returns
XOF reader from which results of arbitrary length can be read. Note that
these functions do not implement `Digest`, so lower-level traits have to
be imported:

```rust
use sha3::{Shake128, digest::{Update, ExtendableOutput, XofReader}};
use hex_literal::hex;

let mut hasher = Shake128::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("5881092dd818bf5cf8a3"));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

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

[examples section]: https://github.com/RustCrypto/hashes#Examples
[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[SHA-3 Derived Functions]: https://csrc.nist.gov/pubs/sp/800/185/final