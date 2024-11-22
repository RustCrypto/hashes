# RustCrypto: Shabal

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Shabal] cryptographic hash algorithm.

There are 5 standard algorithms specified in the Shabal standard: [`Shabal192`], [`Shabal224`], [`Shabal256`], [`Shabal384`], [`Shabal512`].

## Examples

```rust
use shabal::{Shabal256, Digest};
use hex_literal::hex;

let mut hasher = Shabal256::new();
hasher.update(b"helloworld");
let hash = hasher.finalize();

assert_eq!(hash, hex!("d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8");
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

[crate-image]: https://img.shields.io/crates/v/shabal.svg
[crate-link]: https://crates.io/crates/shabal
[docs-image]: https://docs.rs/shabal/badge.svg
[docs-link]: https://docs.rs/shabal/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/shabal/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Ashabal

[//]: # (general links)

[Shabal]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
[examples section]: https://github.com/RustCrypto/hashes#Examples
