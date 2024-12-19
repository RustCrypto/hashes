# RustCrypto: BelT hash

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [BelT] hash function specified in [STB 34.101.31-2020].

## Examples
```rust
use belt_hash::{BeltHash, Digest};
use hex_literal::hex;

let mut hasher = BeltHash::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("afb175816416fbadad4629ecbd78e1887789881f2d2e5b80c22a746b7ac7ba88"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "afb175816416fbadad4629ecbd78e1887789881f2d2e5b80c22a746b7ac7ba88");
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

[crate-image]: https://img.shields.io/crates/v/belt-hash.svg
[crate-link]: https://crates.io/crates/belt-hash
[docs-image]: https://docs.rs/belt-hash/badge.svg
[docs-link]: https://docs.rs/belt-hash
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/belt-hash/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Abelt-hash

[//]: # (general links)

[BelT]: https://ru.wikipedia.org/wiki/BelT
[STB 34.101.31-2020]: http://apmi.bsu.by/assets/files/std/belt-spec371.pdf
[examples section]: https://github.com/RustCrypto/hashes#Examples
