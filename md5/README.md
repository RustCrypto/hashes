# RustCrypto: MD5

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [MD5] cryptographic hash algorithm.

## ⚠️ Security Warning

This crate is provided for the purposes of legacy interoperability with
protocols and systems which mandate the use of MD5.

However, MD5 is [cryptographically broken and unsuitable for further use][1].

Collision attacks against MD5 are both practical and trivial, and
[theoretical attacks against MD5's preimage resistance have been found][2].

[RFC 6151] advises no new IETF protocols can be designed MD5-based constructions,
including HMAC-MD5.

## Examples

```rust
use md5::{Md5, Digest};
use hex_literal::hex;

let mut hasher = Md5::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("5eb63bbbe01eeed093cb22bb8f5acdc3"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "5eb63bbbe01eeed093cb22bb8f5acdc3");
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

[crate-image]: https://img.shields.io/crates/v/md-5.svg
[crate-link]: https://crates.io/crates/md-5
[docs-image]: https://docs.rs/md-5/badge.svg
[docs-link]: https://docs.rs/md-5/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/md5.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/md5.yml?query=branch:master

[//]: # (general links)

[MD5]: https://en.wikipedia.org/wiki/MD5
[examples section]: https://github.com/RustCrypto/hashes#Examples
[1]: https://www.kb.cert.org/vuls/id/836068
[2]: https://dl.acm.org/citation.cfm?id=1724151
[RFC 6151]: https://tools.ietf.org/html/rfc6151
