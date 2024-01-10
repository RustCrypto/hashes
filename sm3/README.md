# RustCrypto: SM3

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SM3] cryptographic hash function defined
in OSCCA GM/T 0004-2012.

## Examples

```rust
use sm3::{Digest, Sm3};
use hex_literal::hex;

let mut hasher = Sm3::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88"));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.71** or higher.

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

[crate-image]: https://img.shields.io/crates/v/sm3.svg
[crate-link]: https://crates.io/crates/sm3
[docs-image]: https://docs.rs/sm3/badge.svg
[docs-link]: https://docs.rs/sm3/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.71+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/sm3/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Asm3

[//]: # (general links)

[SM3]: https://en.wikipedia.org/wiki/SM3_(hash_function)
[examples section]: https://github.com/RustCrypto/hashes#Examples
