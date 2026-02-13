# RustCrypto: Hashes

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]

Collection of [cryptographic hash functions][1] written in pure Rust.

All algorithms reside in separate crates and are implemented using traits from [`digest`] crate.
Usage examples are provided in `digest` and hash implementation crate docs.
Additionally all crates do not require the standard library (i.e. `no_std` capable) and can be
easily used for bare-metal or WebAssembly programming by disabling default crate features.

## Supported Algorithms

**Note:** For new applications, or where compatibility with other existing standards is not a primary concern, we strongly recommend to use either [BLAKE3][`blake3`], SHA-2 or SHA-3.

| Algorithm | Crate | Crates.io | Documentation | MSRV | [Security] |
|-----------|-------|:---------:|:-------------:|:----:|:----------:|
| [Ascon] hash | [`ascon‑hash256`] | [![crates.io](https://img.shields.io/crates/v/ascon-hash256.svg)](https://crates.io/crates/ascon-hash256) | [![Documentation](https://docs.rs/ascon-hash256/badge.svg)](https://docs.rs/ascon-hash256) | 1.85 | :green_heart: |
| [Bash] hash | [`bash‑hash`] | [![crates.io](https://img.shields.io/crates/v/bash-hash.svg)](https://crates.io/crates/bash-hash) | [![Documentation](https://docs.rs/bash-hash/badge.svg)](https://docs.rs/bash-hash) | 1.85 | :green_heart: |
| [BelT] hash | [`belt‑hash`] | [![crates.io](https://img.shields.io/crates/v/belt-hash.svg)](https://crates.io/crates/belt-hash) | [![Documentation](https://docs.rs/belt-hash/badge.svg)](https://docs.rs/belt-hash) | 1.85 | :green_heart: |
| [BLAKE2] | [`blake2`] | [![crates.io](https://img.shields.io/crates/v/blake2.svg)](https://crates.io/crates/blake2) | [![Documentation](https://docs.rs/blake2/badge.svg)](https://docs.rs/blake2) | 1.85 | :green_heart: |
| [FSB] | [`fsb`] | [![crates.io](https://img.shields.io/crates/v/fsb.svg)](https://crates.io/crates/fsb) | [![Documentation](https://docs.rs/fsb/badge.svg)](https://docs.rs/fsb) | 1.85 | :green_heart: |
| [GOST R 34.11-94][GOST94] | [`gost94`] | [![crates.io](https://img.shields.io/crates/v/gost94.svg)](https://crates.io/crates/gost94) | [![Documentation](https://docs.rs/gost94/badge.svg)](https://docs.rs/gost94) | 1.85 | :yellow_heart: |
| [Grøstl] (Groestl) | [`groestl`] | [![crates.io](https://img.shields.io/crates/v/groestl.svg)](https://crates.io/crates/groestl) | [![Documentation](https://docs.rs/groestl/badge.svg)](https://docs.rs/groestl) | 1.85 | :green_heart: |
| [JH] | [`jh`] | [![crates.io](https://img.shields.io/crates/v/jh.svg)](https://crates.io/crates/jh) | [![Documentation](https://docs.rs/jh/badge.svg)](https://docs.rs/jh) | 1.85 | :green_heart: |
| [KangarooTwelve] | [`k12`] | [![crates.io](https://img.shields.io/crates/v/k12.svg)](https://crates.io/crates/k12) | [![Documentation](https://docs.rs/k12/badge.svg)](https://docs.rs/k12) | 1.85 | :green_heart: |
| [Kupyna] | [`kupyna`] | [![crates.io](https://img.shields.io/crates/v/kupyna.svg)](https://crates.io/crates/kupyna) | [![Documentation](https://docs.rs/kupyna/badge.svg)](https://docs.rs/kupyna) | 1.85 | :green_heart: |
| [MD2] | [`md2`] | [![crates.io](https://img.shields.io/crates/v/md2.svg)](https://crates.io/crates/md2) | [![Documentation](https://docs.rs/md2/badge.svg)](https://docs.rs/md2) | 1.85 | :broken_heart: |
| [MD4] | [`md4`] | [![crates.io](https://img.shields.io/crates/v/md4.svg)](https://crates.io/crates/md4) | [![Documentation](https://docs.rs/md4/badge.svg)](https://docs.rs/md4) | 1.85 | :broken_heart: |
| [MD5] | [`md5`] [:exclamation:] | [![crates.io](https://img.shields.io/crates/v/md-5.svg)](https://crates.io/crates/md-5) | [![Documentation](https://docs.rs/md-5/badge.svg)](https://docs.rs/md-5) | 1.85 | :broken_heart: |
| [RIPEMD] | [`ripemd`] | [![crates.io](https://img.shields.io/crates/v/ripemd.svg)](https://crates.io/crates/ripemd) | [![Documentation](https://docs.rs/ripemd/badge.svg)](https://docs.rs/ripemd) | 1.85 | :green_heart: |
| [SHA-1] | [`sha1`] | [![crates.io](https://img.shields.io/crates/v/sha1.svg)](https://crates.io/crates/sha1) | [![Documentation](https://docs.rs/sha1/badge.svg)](https://docs.rs/sha1) | 1.85 | :broken_heart: |
| [SHA-1 Checked] | [`sha1-checked`] | [![crates.io](https://img.shields.io/crates/v/sha1-checked.svg)](https://crates.io/crates/sha1-checked) | [![Documentation](https://docs.rs/sha1-checked/badge.svg)](https://docs.rs/sha1-checked) | 1.85 | :yellow_heart: |
| [SHA-2] | [`sha2`] | [![crates.io](https://img.shields.io/crates/v/sha2.svg)](https://crates.io/crates/sha2) | [![Documentation](https://docs.rs/sha2/badge.svg)](https://docs.rs/sha2) | 1.85 | :green_heart: |
| [SHA-3] (Keccak) | [`sha3`] | [![crates.io](https://img.shields.io/crates/v/sha3.svg)](https://crates.io/crates/sha3) | [![Documentation](https://docs.rs/sha3/badge.svg)](https://docs.rs/sha3) | 1.85 | :green_heart: |
| [SHABAL] | [`shabal`] | [![crates.io](https://img.shields.io/crates/v/shabal.svg)](https://crates.io/crates/shabal) | [![Documentation](https://docs.rs/shabal/badge.svg)](https://docs.rs/shabal) | 1.85 | :green_heart: |
| [Skein] | [`skein`] | [![crates.io](https://img.shields.io/crates/v/skein.svg)](https://crates.io/crates/skein) | [![Documentation](https://docs.rs/skein/badge.svg)](https://docs.rs/skein) | 1.85 | :green_heart: |
| [SM3] (OSCCA GM/T 0004-2012) | [`sm3`] | [![crates.io](https://img.shields.io/crates/v/sm3.svg)](https://crates.io/crates/sm3) | [![Documentation](https://docs.rs/sm3/badge.svg)](https://docs.rs/sm3) | 1.85 | :green_heart: |
| [Streebog] (GOST R 34.11-2012) | [`streebog`] | [![crates.io](https://img.shields.io/crates/v/streebog.svg)](https://crates.io/crates/streebog) | [![Documentation](https://docs.rs/streebog/badge.svg)](https://docs.rs/streebog) | 1.85 | :yellow_heart: |
| [Tiger] | [`tiger`] | [![crates.io](https://img.shields.io/crates/v/tiger.svg)](https://crates.io/crates/tiger) | [![Documentation](https://docs.rs/tiger/badge.svg)](https://docs.rs/tiger) | 1.85 | :green_heart: |
| [Whirlpool] | [`whirlpool`] | [![crates.io](https://img.shields.io/crates/v/whirlpool.svg)](https://crates.io/crates/whirlpool) | [![Documentation](https://docs.rs/whirlpool/badge.svg)](https://docs.rs/whirlpool) | 1.85 | :green_heart: |

NOTE: the [`blake3`] crate implements the `digest` traits used by the rest of the hashes in this repository, but is maintained by the BLAKE3 team.

[Security]: https://en.wikipedia.org/wiki/Hash_function_security_summary
[:exclamation:]: #crate-names

### Security Level Legend

The following describes the security level ratings associated with each hash function (i.e. algorithms, not the specific implementation):

| Heart          | Description |
|:--------------:|-------------|
| :green_heart:  | No known successful attacks |
| :yellow_heart: | Theoretical break: security lower than claimed |
| :broken_heart: | Attack demonstrated in practice: avoid if at all possible |

See the [Security] page on Wikipedia for more information.

### Crate Names

Whenever possible crates are published under the same name as the crate folder.
Owners of `md5` [declined](https://github.com/stainless-steel/md5/pull/) to participate in this project.
This crate does not implement the [`digest`] traits, so it is not interoperable with the RustCrypto ecosystem.
This is why we publish our MD5 implementation as `md-5` and mark it with the :exclamation: mark.
Note that the library itself is named as `md5`, i.e. inside `use` statements you should use `md5`, not `md_5`.

## License

All crates in this repository are licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[deps-image]: https://deps.rs/repo/github/RustCrypto/hashes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/hashes

[//]: # (crates)

[`ascon‑hash256`]: ./ascon-hash256
[`bash‑hash`]: ./bash-hash
[`belt‑hash`]: ./belt-hash
[`blake2`]: ./blake2
[`fsb`]: ./fsb
[`gost94`]: ./gost94
[`groestl`]: ./groestl
[`jh`]: ./jh
[`k12`]: ./k12
[`kupyna`]: ./kupyna
[`md2`]: ./md2
[`md4`]: ./md4
[`md5`]: ./md5
[`ripemd`]: ./ripemd
[`sha1`]: ./sha1
[`sha1-checked`]: ./sha1-checked
[`sha2`]: ./sha2
[`sha3`]: ./sha3
[`shabal`]: ./shabal
[`skein`]: ./skein
[`sm3`]: ./sm3
[`streebog`]: ./streebog
[`tiger`]: ./tiger
[`whirlpool`]: ./whirlpool

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[`blake3`]: https://github.com/BLAKE3-team/BLAKE3
[`base16ct`]: https://docs.rs/base16ct
[`base64ct`]: https://docs.rs/base64ct
[`digest`]: https://docs.rs/digest
[`Digest`]: https://docs.rs/digest/0.10.0/digest/trait.Digest.html
[`Digest::digest`]: https://docs.rs/digest/0.10.0/digest/trait.Digest.html#tymethod.digest
[`DynDigest`]: https://docs.rs/digest/0.10.0/digest/trait.DynDigest.html
[`generic-array`]: https://docs.rs/generic-array
[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[`Read`]: https://doc.rust-lang.org/std/io/trait.Read.html
[`Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
[`hmac`]: https://docs.rs/hmac
[RustCrypto/MACs]: https://github.com/RustCrypto/MACs

[//]: # (algorithms)

[Ascon]: https://ascon.iaik.tugraz.at
[Bash]: https://apmi.bsu.by/assets/files/std/bash-spec241.pdf
[BelT]: https://ru.wikipedia.org/wiki/BelT
[BLAKE2]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
[FSB]: https://en.wikipedia.org/wiki/Fast_syndrome-based_hash
[GOST94]: https://en.wikipedia.org/wiki/GOST_(hash_function)
[Grøstl]: https://en.wikipedia.org/wiki/Grøstl
[JH]: https://www3.ntu.edu.sg/home/wuhj/research/jh
[KangarooTwelve]: https://keccak.team/kangarootwelve.html
[Kupyna]: https://eprint.iacr.org/2015/885.pdf
[MD2]: https://en.wikipedia.org/wiki/MD2_(cryptography)
[MD4]: https://en.wikipedia.org/wiki/MD4
[MD5]: https://en.wikipedia.org/wiki/MD5
[RIPEMD]: https://en.wikipedia.org/wiki/RIPEMD
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[SHA-1 Checked]: https://github.com/cr-marcstevens/sha1collisiondetection
[SHA-2]: https://en.wikipedia.org/wiki/SHA-2
[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[SHABAL]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
[Skein]: https://schneier.com/academic/skein
[SM3]: https://en.wikipedia.org/wiki/SM3_(hash_function)
[Streebog]: https://en.wikipedia.org/wiki/Streebog
[Whirlpool]: https://en.wikipedia.org/wiki/Whirlpool_(cryptography)
[Tiger]: http://www.cs.technion.ac.il/~biham/Reports/Tiger/tiger/tiger.html
