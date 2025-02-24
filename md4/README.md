# RustCrypto: MD4

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [MD4] cryptographic hash algorithm.

## Examples

```rust
use md4::{Md4, Digest};
use hex_literal::hex;

// create a Md4 hasher instance
let mut hasher = Md4::new();

// process input message
hasher.update(b"hello world");

// acquire hash digest in the form of Array,
// which in this case is equivalent to [u8; 16]
let hash = hasher.finalize();
assert_eq!(hash, hex!("aa010fbc1d14c795d86ef98c95479d17"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "aa010fbc1d14c795d86ef98c95479d17");
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

[crate-image]: https://img.shields.io/crates/v/md4.svg
[crate-link]: https://crates.io/crates/md4
[docs-image]: https://docs.rs/md4/badge.svg
[docs-link]: https://docs.rs/md4/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/md4.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/md4.yml?query=branch:master

[//]: # (general links)

[MD4]: https://en.wikipedia.org/wiki/MD4
[examples section]: https://github.com/RustCrypto/hashes#Examples
