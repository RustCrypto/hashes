# RustCrypto: Shabal

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Shabal][1] cryptographic hash algorithm.

[Documentation][docs-link]

## About 
There are 5 standard algorithms specified in the Shabal standard:

* `Shabal192`, which is the `Shabal` algorithm with the result truncated to 192 bits
* `Shabal224`, which is the `Shabal` algorithm with the result truncated to 224 bits
* `Shabal256`, which is the `Shabal` algorithm with the result truncated to 256 bits.
* `Shabal384`, which is the `Shabal` algorithm with the result truncated to 384 bits.
* `Shabal512`, which is the `Shabal` algorithm with the result not truncated.

There is a single Shabal algorithm. All variants have different initialisation and apart
from Shabal512 all truncate the result.

## Usage

```rust
use shabal::{Shabal256, Digest};

// create a Shabal256 hasher instance
let mut hasher = Shabal256::new();

// process input message
hasher.input(b"helloworld");

// acquire hash digest in the form of GenericArray,
// which in this case is equivalent to [u8; 32]
let result = hasher.result();
assert_eq!(result[..], hex!("d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8"));
```

## Minimum Supported Rust Version

Rust **1.41** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/shabal.svg
[crate-link]: https://crates.io/crates/shabal
[docs-image]: https://docs.rs/shabal/badge.svg
[docs-link]: https://docs.rs/shabal/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.41+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/shabal/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Ashabal

[//]: # (general links)

[1]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
