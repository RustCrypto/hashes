# RustCrypto: Streebog

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Streebog] cryptographic hash function defined in GOST R 34.11-2012.

## Examples

```rust
use streebog::{Digest, Streebog256, Streebog512};
use hex_literal::hex;

let mut hasher = Streebog256::new();
hasher.update("The quick brown fox jumps over the lazy dog");
let hash256 = hasher.finalize();

assert_eq!(hash256, hex!("3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash256 = base16ct::lower::encode_string(&hash256);
assert_eq!(hex_hash256, "3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4");

// Same example for Streebog-512
let mut hasher = Streebog512::new();
hasher.update("The quick brown fox jumps over the lazy dog.");
let hash512 = hasher.finalize();

assert_eq!(hash512, hex!(
    "fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be8"
    "2d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070"
));
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

[crate-image]: https://img.shields.io/crates/v/streebog.svg
[crate-link]: https://crates.io/crates/streebog
[docs-image]: https://docs.rs/streebog/badge.svg
[docs-link]: https://docs.rs/streebog/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/streebog.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/streebog.yml?query=branch:master

[//]: # (general links)

[Streebog]: https://en.wikipedia.org/wiki/Streebog
[`digest`]: https://docs.rs/digest
