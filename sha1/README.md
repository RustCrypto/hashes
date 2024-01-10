# RustCrypto: SHA-1

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SHA-1] cryptographic hash algorithm.

## 🚨 Warning: Cryptographically Broken! 🚨

The SHA-1 hash function should be considered cryptographically broken and
unsuitable for further use in any security critical capacity, as it is
[practically vulnerable to chosen-prefix collisions][1].

We provide this crate for legacy interoperability purposes only.

## Examples

### One-shot API

```rust
use hex_literal::hex;
use sha1::{Sha1, Digest};

let result = Sha1::digest(b"hello world");
assert_eq!(result, hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
```

### Incremental API

```rust
use hex_literal::hex;
use sha1::{Sha1, Digest};

let mut hasher = Sha1::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));
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

[crate-image]: https://img.shields.io/crates/v/sha1.svg
[crate-link]: https://crates.io/crates/sha1
[docs-image]: https://docs.rs/sha1/badge.svg
[docs-link]: https://docs.rs/sha1/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.71+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/sha1/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Asha1

[//]: # (general links)

[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[1]: https://sha-mbles.github.io/
[examples section]: https://github.com/RustCrypto/hashes#Examples
