# RustCrypto: FSB

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [FSB] cryptographic hash algorithms.

There are 5 standard versions of the FSB hash function:

* `FSB-160`
* `FSB-224`
* `FSB-256`
* `FSB-384`
* `FSB-512`

## Examples

Output size of FSB-256 is fixed, so its functionality is usually
accessed via the `Digest` trait:

```rust
use fsb::{Digest, Fsb256};
use hex_literal::hex;

let mut hasher = Fsb256::new();
hasher.update(b"hello");
let hash = hasher.finalize();

assert_eq!(hash, hex!("0f036dc3761aed2cba9de586a85976eedde6fa8f115c0190763decc02f28edbc"));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.71** or higher.

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

[crate-image]: https://img.shields.io/crates/v/fsb.svg
[crate-link]: https://crates.io/crates/fsb
[docs-image]: https://docs.rs/fsb/badge.svg
[docs-link]: https://docs.rs/fsb/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[rustc-image]: https://img.shields.io/badge/rustc-1.71+-blue.svg
[build-image]: https://github.com/RustCrypto/hashes/workflows/fsb/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Afsb

[//]: # (general links)

[FSB]: https://www.paris.inria.fr/secret/CBCrypto/index.php?pg=fsb
[examples section]: https://github.com/RustCrypto/hashes#Examples
