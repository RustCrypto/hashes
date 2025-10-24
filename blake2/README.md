# RustCrypto: BLAKE2

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [BLAKE2] hash function family.

## Examples

### Fixed output size

```rust
use blake2::{Blake2b512, Blake2s256, Digest};
use hex_literal::hex;

// create a Blake2b512 object
let mut hasher = Blake2b512::new();

// write input message
hasher.update(b"hello world");

// read hash digest and consume hasher
let hash = hasher.finalize();
assert_eq!(hash, hex!(
    "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbc"
    "c05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0"
));

// same example for Blake2s256:
let mut hasher = Blake2s256::new();
hasher.update(b"hello world");
let hash = hasher.finalize();
assert_eq!(hash, hex!("9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b");
```

Also, see the [examples section] in the RustCrypto/hashes readme.

### Variable output size

This implementation supports output sizes variable at compile time:

```rust
use blake2::{Blake2b, Digest, digest::consts::U10};
use hex_literal::hex;

type Blake2b80 = Blake2b<U10>;

let mut hasher = Blake2b80::new();
hasher.update(b"my_input");
let res = hasher.finalize();
assert_eq!(res, hex!("2cc55c84e416924e6400"));
```

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

[crate-image]: https://img.shields.io/crates/v/blake2.svg
[crate-link]: https://crates.io/crates/blake2
[docs-image]: https://docs.rs/blake2/badge.svg
[docs-link]: https://docs.rs/blake2/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/blake2.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/blake2.yml?query=branch:master

[//]: # (general links)

[BLAKE2]: https://blake2.net/
[examples section]: https://github.com/RustCrypto/hashes#Examples
