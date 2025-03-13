# RustCrypto: Kupyna


[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Pure Rust implementation of the [Kupyna] cryptographic hash function defined under DSTU 7564:2014.

## Examples

```rust
use hex_literal::hex;
use kupyna::{Digest, Kupyna256};

let mut hasher = Kupyna256::default();
hasher.update(b"my message");
let hash = hasher.finalize();

assert_eq!(hash, hex!("538e2e238142df05e954702aa75d6942cebe30d44bd514df365d13bdcb6b1458"));

// Hex-encode hash using https://docs.rs/base16ct
let hex_hash = base16ct::lower::encode_string(&hash);
assert_eq!(hex_hash, "538e2e238142df05e954702aa75d6942cebe30d44bd514df365d13bdcb6b1458");
```

Also, see the [examples section] in the RustCrypto/hashes readme.

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

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.71+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes

[//]: # (general links)

[Kupyna]: https://eprint.iacr.org/2015/885.pdf
[examples section]: https://github.com/RustCrypto/hashes#Examples
