# RustCrypto: MD2

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [MD2] cryptographic hash algorithm.

## Examples

```rust
use md2::{Md2, Digest};
use hex_literal::hex;

let mut hasher = Md2::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("d9cce882ee690a5c1ce70beff3a78c77"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "d9cce882ee690a5c1ce70beff3a78c77");
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

[crate-image]: https://img.shields.io/crates/v/md2.svg
[crate-link]: https://crates.io/crates/md2
[docs-image]: https://docs.rs/md2/badge.svg
[docs-link]: https://docs.rs/md2/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/md2.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/md2.yml?query=branch:master

[//]: # (general links)

[MD2]: https://en.wikipedia.org/wiki/MD2_(hash_function)
[`digest`]: https://docs.rs/digest
