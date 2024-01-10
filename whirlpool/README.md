# RustCrypto: Whirlpool

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Whirlpool] cryptographic hash algorithm.

This is the algorithm recommended by NESSIE (New European Schemes for
Signatures, Integrity and Encryption; an European research project).

The constants used by Whirlpool were changed twice (2001 and 2003) - this
crate only implements the most recent standard. The two older Whirlpool
implementations (sometimes called Whirlpool-0 (pre 2001) and Whirlpool-T
(pre 2003)) were not used much anyway (both have never been recommended
by NESSIE).

For details see this [page][1].

## Examples

```rust
use whirlpool::{Whirlpool, Digest};
use hex_literal::hex;

let mut hasher = Whirlpool::new();
hasher.update(b"Hello Whirlpool");
let hash = hasher.finalize();

assert_eq!(hash, hex!(
    "8eaccdc136903c458ea0b1376be2a5fc9dc5b8ce8892a3b4f43366e2610c206c"
    "a373816495e63db0fff2ff25f75aa7162f332c9f518c3036456502a8414d300a"
));
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

[crate-image]: https://img.shields.io/crates/v/whirlpool.svg
[crate-link]: https://crates.io/crates/whirlpool
[docs-image]: https://docs.rs/whirlpool/badge.svg
[docs-link]: https://docs.rs/whirlpool/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.71+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/workflows/whirlpool/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions?query=workflow%3Awhirlpool

[//]: # (general links)

[Whirlpool]: https://en.wikipedia.org/wiki/Whirlpool_(hash_function)
[1]: https://web.archive.org/web/20171129084214/http://www.larc.usp.br/~pbarreto/WhirlpoolPage.html
[examples section]: https://github.com/RustCrypto/hashes#Examples
