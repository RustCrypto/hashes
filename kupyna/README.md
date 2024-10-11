# RustCrypto: Kupyna


![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]

Pure Rust implementation of the [Kupyna] cryptographic hash function defined under DSTU 7564:2014.
## Examples

```rust
use kupyna::KupynaH;

let message = b"Hello, World!".to_vec();
let _message_length = 0;

let kupyna = KupynaH::new(512);

let hash_code = kupyna.hash(message, None).unwrap();

println!("{:02X?}", hash_code);
```

Also, see the [examples section] in the RustCrypto/hashes readme.

## Minimum Supported Rust Version

Rust **1.71** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

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
