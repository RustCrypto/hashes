# RustCrypto: Ascon-Hash256 and Ascon-XOF128

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the lightweight cryptographic hash function [Ascon-Hash256][1] and the
extendable output functions (XOF) Ascon-XOF128.

## Security Notes

No security audits of this crate have ever been performed.

USE AT YOUR OWN RISK!

## Examples
Fixed output size hashing:
```rust
use ascon_hash256::{AsconHash256, Digest};
use hex_literal::hex;

let mut hasher = AsconHash256::new();
hasher.update(b"some bytes");
let hash = hasher.finalize();

assert_eq!(hash, hex!("e909c2f6da9cb3028423265c8f23fc2d26bfc0f3db704683ef16b787a945ed68"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "e909c2f6da9cb3028423265c8f23fc2d26bfc0f3db704683ef16b787a945ed68");
```

XOF hashing:
```rust
use ascon_hash256::{AsconXof128, ExtendableOutput, Update, XofReader};
use hex_literal::hex;

let mut xof = AsconXof128::default();
xof.update(b"some bytes");
let mut reader = xof.finalize_xof();
let mut dst = [0u8; 5];
reader.read(&mut dst);
assert_eq!(dst, hex!("8c7dd114a0"));
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

[crate-image]: https://img.shields.io/crates/v/ascon-hash256.svg
[crate-link]: https://crates.io/crates/ascon-hash256
[docs-image]: https://docs.rs/ascon-hash256/badge.svg
[docs-link]: https://docs.rs/ascon-hash256/
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/ascon-hash256.yml/badge.svg
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/ascon-hash256.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes

[//]: # (general links)

[1]: https://doi.org/10.6028/NIST.SP.800-232.ipd
[`digest`]: https://docs.rs/digest
