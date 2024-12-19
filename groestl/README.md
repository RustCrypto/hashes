# RustCrypto: Grøstl

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Grøstl] cryptographic hash function.

## Examples

```rust
use groestl::{Digest, Groestl256};
use hex_literal::hex;

let mut hasher = Groestl256::default();
hasher.update(b"my message");
let hash = hasher.finalize();

assert_eq!(hash, hex!("dc0283ca481efa76b7c19dd5a0b763dff0e867451bd9488a9c59f6c8b8047a86"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "dc0283ca481efa76b7c19dd5a0b763dff0e867451bd9488a9c59f6c8b8047a86");
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

[crate-image]: https://img.shields.io/crates/v/groestl.svg
[crate-link]: https://crates.io/crates/groestl
[docs-image]: https://docs.rs/groestl/badge.svg
[docs-link]: https://docs.rs/groestl/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/groestl/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Agroestl

[//]: # (general links)

[Grøstl]: https://en.wikipedia.org/wiki/Grøstl
[examples section]: https://github.com/RustCrypto/hashes#Examples
