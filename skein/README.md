# RustCrypto: Skein

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Implementation of the [Skein] family of cryptographic hash algorithms.

There are 3 standard versions of the Skein hash function: `Skein256`, `Skein512`, `Skein1024`.

Output size of the Skein hash functions is arbitrary, so it has to be
fixed using additional type parameter.

## Examples

```rust
use hex_literal::hex;
use skein::{Digest, Skein512_256};

let mut hasher = Skein512_256::new();
hasher.update(b"The quick brown fox ");
hasher.update(b"jumps over the lazy dog");
let hash = hasher.finalize();

assert_eq!(hash, hex!("b3250457e05d3060b1a4bbc1428bc75a3f525ca389aeab96cfa34638d96e492a"));
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

[crate-image]: https://img.shields.io/crates/v/skein.svg
[crate-link]: https://crates.io/crates/skein
[docs-image]: https://docs.rs/skein/badge.svg
[docs-link]: https://docs.rs/skein/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/skein.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/skein.yml?query=branch:master

[//]: # (general links)

[Skein]: https://schneier.com/academic/skein
[`digest`]: https://docs.rs/digest
