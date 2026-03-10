# RustCrypto: bash prg hash

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the bash prg hash function specified in [STB 34.101.77-2020].

## Examples
```rust
use hex_literal::hex;
use bash_prg_hash::{BashPrgHash2561, Digest};
use digest::{Update, ExtendableOutput};
let mut hasher = BashPrgHash2561::default();
hasher.update(b"hello world!");

let mut hash = [0u8; 32];
hasher.finalize_xof_into(&mut hash);

assert_eq!(hash, hex!("0C6B82907AE77386DDF0BA2D7CFDDD99F79A9B0094E545AEF8968A99440F5185"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::upper::encode_string(&hash);
assert_eq!(hex_hash, "0C6B82907AE77386DDF0BA2D7CFDDD99F79A9B0094E545AEF8968A99440F5185");
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
