# RustCrypto: SHA-2

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [SHA-2] cryptographic hash algorithms.

There are 6 standard algorithms specified in the SHA-2 standard: 
`Sha224`, `Sha256`, `Sha512_224`, `Sha512_256`, `Sha384`, and `Sha512`.

Algorithmically, there are only 2 core algorithms: SHA-256 and SHA-512.
All other algorithms are just applications of these with different initial
hash values, and truncated to different digest bit lengths. The first two
algorithms in the list are based on SHA-256, while the last four are based
on SHA-512.

## Examples

### One-shot API

```rust
use sha2::{Sha256, Digest};
use hex_literal::hex;

let hash = Sha256::digest(b"hello world");
assert_eq!(hash, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
```

### Incremental API

```rust
use sha2::{Sha256, Sha512, Digest};
use hex_literal::hex;

let mut hasher = Sha256::new();
hasher.update(b"hello ");
hasher.update(b"world");
let hash256 = hasher.finalize();

assert_eq!(hash256, hex!("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));

let mut hasher = Sha512::new();
hasher.update(b"hello world");
let hash512 = hasher.finalize();

assert_eq!(hash512, hex!(
    "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f"
    "989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.72** or higher.

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

[crate-image]: https://img.shields.io/crates/v/sha2.svg
[crate-link]: https://crates.io/crates/sha2
[docs-image]: https://docs.rs/sha2/badge.svg
[docs-link]: https://docs.rs/sha2/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.72+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/sha2/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Asha2

[//]: # (general links)

[SHA-2]: https://en.wikipedia.org/wiki/SHA-2
[examples section]: https://github.com/RustCrypto/hashes#Examples
