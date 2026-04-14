# RustCrypto: SHA-3

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Implementation of the [TurboSHAKE] family of extendable-output functions (XOFs).

## Examples

SHAKE functions have an extendable output, so finalization method returns
XOF reader from which results of arbitrary length can be read. Note that
these functions do not implement `Digest`, so lower-level traits have to
be imported:

```rust
use turbo_shake::TurboShake128;
use turbo_shake::digest::{Update, ExtendableOutput, XofReader};
use hex_literal::hex;

// With the default domain separator.
// 
// Note that we have to use `<TurboShake128>` because of
// the inadequate handling of defaults in Rust.
// Alternatively, you could use `let mut hasher: TurboShake128 = Default::default();`
// or `TurboShake128::<DEFAULT_DS>::default()`.
let mut hasher = <TurboShake128>::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("dcf1646dfe993a8eb6b7"));
reader.read(&mut buf);
assert_eq!(buf, hex!("82d1faaca6d82416a5dc"));

// With a custom domain separator
let mut hasher = TurboShake128::<0x10>::default();
hasher.update(b"abc");
let mut reader = hasher.finalize_xof();
let mut buf = [0u8; 10];
reader.read(&mut buf);
assert_eq!(buf, hex!("6702f7b19ea87087ed0f"));
reader.read(&mut buf);
assert_eq!(buf, hex!("45a2fa692bc18c3526d3"));
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

[crate-image]: https://img.shields.io/crates/v/turbo-shake.svg
[crate-link]: https://crates.io/crates/turbo-shake
[docs-image]: https://docs.rs/turbo-shake/badge.svg
[docs-link]: https://docs.rs/turbo-shake
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/turbo-shake.yml/badge.svg?branch=master
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/turbo-shake.yml?query=branch:master

[//]: # (general links)

[TurboSHAKE]: https://keccak.team/turboshake.html
[`digest`]: https://docs.rs/digest
