# RustCrypto: bash hash

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the bash hash function specified in [STB 34.101.77-2020].

## Examples
```rust
use bash_hash::{BashHash256, Digest};
use hex_literal::hex;

let mut hasher = BashHash256::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("2FC08EEC942378C0F8A6E5F1890D907B706BE393B0386E20A73D4D17A46BBD10"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::upper::encode_string(&hash);
assert_eq!(hex_hash, "2FC08EEC942378C0F8A6E5F1890D907B706BE393B0386E20A73D4D17A46BBD10");
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

[crate-image]: https://img.shields.io/crates/v/belt-hash.svg
[crate-link]: https://crates.io/crates/belt-hash
[docs-image]: https://docs.rs/belt-hash/badge.svg
[docs-link]: https://docs.rs/belt-hash
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/belt-hash.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/belt-hash.yml?query=branch:master

[//]: # (general links)

[STB 34.101.77-2020]: http://apmi.bsu.by/assets/files/std/bash-spec241.pdf
[examples section]: https://github.com/RustCrypto/hashes#Examples
