# RustCrypto: Ascon-XOF128

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Ascon-XOF128] extendable output function (XOF).

## Examples

Ascon-XOF128 has an extendable output, so finalization methods return
XOF reader from which results of arbitrary length can be read.

```rust
use ascon_xof128::{AsconXof128, ExtendableOutput, Update, XofReader};
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

[crate-image]: https://img.shields.io/crates/v/ascon-xof128.svg
[crate-link]: https://crates.io/crates/ascon-xof128
[docs-image]: https://docs.rs/ascon-xof128/badge.svg
[docs-link]: https://docs.rs/ascon-xof128/
[build-image]: https://github.com/RustCrypto/hashes/actions/workflows/ascon-xof128.yml/badge.svg
[build-link]: https://github.com/RustCrypto/hashes/actions/workflows/ascon-xof128.yml
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes

[//]: # (general links)

[Ascon-XOF128]: https://doi.org/10.6028/NIST.SP.800-232.ipd
[`digest`]: https://docs.rs/digest
