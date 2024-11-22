# RustCrypto: RIPEMD

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [RIPEMD] cryptographic hash.

This crate implements only the modified 1996 versions, not the original
one from 1992.

Note that RIPEMD-256 provides only the same security as RIPEMD-128,
and RIPEMD-320 provides only the same security as RIPEMD-160.

## Examples

```rust
use ripemd::{Ripemd160, Ripemd320, Digest};
use hex_literal::hex;

let mut hasher = Ripemd160::new();
hasher.update(b"Hello world!");
let hash160 = hasher.finalize();

assert_eq!(hash160, hex!("7f772647d88750add82d8e1a7a3e5c0902a346a3"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash160 = base16ct::lower::encode_string(&hash160);
assert_eq!(hex_hash160, "7f772647d88750add82d8e1a7a3e5c0902a346a3");

// Same example for RIPEMD-320
let mut hasher = Ripemd320::new();
hasher.update(b"Hello world!");
let hash320 = hasher.finalize();

assert_eq!(hash320, hex!(
    "f1c1c231d301abcf2d7daae0269ff3e7bc68e623"
    "ad723aa068d316b056d26b7d1bb6f0cc0f28336d"
));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/ripemd.svg
[crate-link]: https://crates.io/crates/ripemd
[docs-image]: https://docs.rs/ripemd/badge.svg
[docs-link]: https://docs.rs/ripemd/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/ripemd/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Aripemd160

[//]: # (general links)

[RIPEMD]: https://en.wikipedia.org/wiki/RIPEMD
[examples section]: https://github.com/RustCrypto/hashes#Examples
