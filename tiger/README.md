# RustCrypto: Tiger

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Tiger] cryptographic hash algorithms.

Tiger2 is a variant of the original Tiger with a small padding tweak.

## Examples

```rust
use tiger::{Tiger, Digest};
use hex_literal::hex;

let mut hasher = Tiger::new();
hasher.update(b"hello world");
let hash = hasher.finalize();

assert_eq!(hash, hex!("4c8fbddae0b6f25832af45e7c62811bb64ec3e43691e9cc3"));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.74** or higher.

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
for inclusion in the work by you, as defined in the Apache-2.0 license, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/tiger.svg
[crate-link]: https://crates.io/crates/tiger
[docs-image]: https://docs.rs/tiger/badge.svg
[docs-link]: https://docs.rs/tiger/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.74+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/tiger/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Atiger

[//]: # (general links)

[Tiger]: http://www.cs.technion.ac.il/~biham/Reports/Tiger/tiger/tiger.html
[examples section]: https://github.com/RustCrypto/hashes#Examples
