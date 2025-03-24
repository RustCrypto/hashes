# RustCrypto: GOST94

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [GOST R 34.11-94] cryptographic hash algorithm.

## Examples

```rust
use gost94::{Gost94CryptoPro, Digest};
use hex_literal::hex;

let mut hasher = Gost94CryptoPro::new();
hasher.update("The quick brown fox jumps over the lazy dog");
let hash = hasher.finalize();

assert_eq!(hash, hex!("9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76");
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Associated OIDs.
There can be a confusion regarding OIDs associated with declared types.
According to the [RFC 4357], the OIDs 1.2.643.2.2.30.1 and 1.2.643.2.2.30.0 are used to identify the hash function parameter sets (CryptoPro vs Test ones).
According to [RFC 4490] the OID 1.2.643.2.2.9 identifies the GOST 34.311-95 (former GOST R 34.11-94) function, but then it continues that this function MUST be used only with the CryptoPro parameter set.

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

[crate-image]: https://img.shields.io/crates/v/gost94.svg
[crate-link]: https://crates.io/crates/gost94
[docs-image]: https://docs.rs/gost94/badge.svg
[docs-link]: https://docs.rs/gost94/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/gost94.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/gost94.yml?query=branch:master

[//]: # (general links)

[GOST R 34.11-94]: https://en.wikipedia.org/wiki/GOST_(hash_function)
[RFC 4357]: https://www.rfc-editor.org/rfc/rfc4357
[RFC 4490]: https://www.rfc-editor.org/rfc/rfc4490
[examples section]: https://github.com/RustCrypto/hashes#Examples
