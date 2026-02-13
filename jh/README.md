# RustCrypto: JH

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [JH] cryptographic hash function.

There are 4 standard versions of the JH hash function:

* JH-224
* JH-256
* JH-384
* JH-512

## Examples

```rust
use jh::{Digest, Jh256};
use hex_literal::hex;

let mut hasher = Jh256::new();
hasher.update(b"hello");
let hash = hasher.finalize();

assert_eq!(hash, hex!("94fd3f4c564957c6754265676bf8b244c707d3ffb294e18af1f2e4f9b8306089"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "94fd3f4c564957c6754265676bf8b244c707d3ffb294e18af1f2e4f9b8306089");
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

[crate-image]: https://img.shields.io/crates/v/jh.svg
[crate-link]: https://crates.io/crates/jh
[docs-image]: https://docs.rs/jh/badge.svg
[docs-link]: https://docs.rs/jh/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/jh.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/jh.yml?query=branch:master

[//]: # (general links)

[JH]: https://en.wikipedia.org/wiki/JH_(hash_function)
[`digest`]: https://docs.rs/digest
