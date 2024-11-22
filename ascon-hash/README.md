# RustCrypto: Ascon

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the lightweight cryptographic hash functions
[AsconHash and AsconAHash][1] and the extendable output functions (XOF) AsconXOF
and AsconAXOF.

## Security Notes

No security audits of this crate have ever been performed.

USE AT YOUR OWN RISK!

## Examples
Fixed output size hashing:
```rust
use ascon_hash::{AsconHash, Digest};
use hex_literal::hex;

let mut hasher = AsconHash::new();
hasher.update(b"some bytes");
let hash = hasher.finalize();

assert_eq!(hash, hex!("b742ca75e57038757059cccc6874714f9dbd7fc5924a7df4e316594fd1426ca8"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "b742ca75e57038757059cccc6874714f9dbd7fc5924a7df4e316594fd1426ca8");
```

XOF hashing:
```rust
use ascon_hash::{AsconXof, ExtendableOutput, Update, XofReader};
use hex_literal::hex;

let mut xof = AsconXof::default();
xof.update(b"some bytes");
let mut reader = xof.finalize_xof();
let mut dst = [0u8; 5];
reader.read(&mut dst);
assert_eq!(dst, hex!("c21972fde9"));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

This crate requires **Rust 1.81** at a minimum.

We may change the MSRV in the future, but it will be accompanied by a minor
version bump.

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

[crate-image]: https://img.shields.io/crates/v/ascon-hash.svg
[crate-link]: https://crates.io/crates/ascon-hash
[docs-image]: https://docs.rs/ascon-hash/badge.svg
[docs-link]: https://docs.rs/ascon-hash/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/ascon-hash/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Aascon-hash

[//]: # (general links)

[1]: https://ascon.iaik.tugraz.at
[examples section]: https://github.com/RustCrypto/hashes#Examples
