# rust-crypto's hashes [![Build Status](https://travis-ci.org/RustCrypto/hashes.svg?branch=master)](https://travis-ci.org/RustCrypto/hashes)
Collection of cryptographic hash functions written in pure Rust. This is the part
of the rust-crypto project.

## Contributions

Contributions are extremely welcome. The most significant needs are help adding
documentation, implementing new algorithms, and general cleanup and improvement
of the code. By submitting a pull request you are agreeing to make you work
available under the license terms of the Rust-Crypto project.

## License

All crates in this repository are dual-licensed under the MIT and Apache 2.0 licenses.

## Supported algorithms
| Name     | Alt name   | Crates.io  | Documentation  | [Security Level] |
| ------------- |:-------------:| :-----:| :-----:| :-----:|
| [BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) |   | [![crates.io](https://img.shields.io/crates/v/blake2.svg)](https://crates.io/crates/blake2) | [![Documentation](https://docs.rs/blake2/badge.svg)](https://docs.rs/blake2) | :green_heart: |
| [GOST94](https://en.wikipedia.org/wiki/GOST_(hash_function)) | GOST R 34.11-94  | [![crates.io](https://img.shields.io/crates/v/gost94.svg)](https://crates.io/crates/gost94) |  [![Documentation](https://docs.rs/gost94/badge.svg)](https://docs.rs/gost94) | :yellow_heart: |
| [Grøstl](https://en.wikipedia.org/wiki/Grøstl) | Groestl  | [![crates.io](https://img.shields.io/crates/v/groestl.svg)](https://crates.io/crates/groestl) |  [![Documentation](https://docs.rs/groestl/badge.svg)](https://docs.rs/groestl) | :green_heart: |
| [MD2](https://en.wikipedia.org/wiki/MD2_(cryptography)) |    | [![crates.io](https://img.shields.io/crates/v/md2.svg)](https://crates.io/crates/md2) |  [![Documentation](https://docs.rs/md2/badge.svg)](https://docs.rs/md2) | :broken_heart: |
| [MD4](https://en.wikipedia.org/wiki/MD4) |    | [![crates.io](https://img.shields.io/crates/v/md4.svg)](https://crates.io/crates/md4) |  [![Documentation](https://docs.rs/md4/badge.svg)](https://docs.rs/md4) | :broken_heart: |
| [MD5](https://en.wikipedia.org/wiki/MD5) |   | [not published](https://github.com/stainless-steel/md5/pull/2) |  | :broken_heart: |
| [RIPEMD-160](https://en.wikipedia.org/wiki/RIPEMD) |    | [![crates.io](https://img.shields.io/crates/v/ripemd160.svg)](https://crates.io/crates/ripemd160) |  [![Documentation](https://docs.rs/ripemd160/badge.svg)](https://docs.rs/ripemd160) | :green_heart: |
| [SHA-1](https://en.wikipedia.org/wiki/SHA-1) |    | [not published](https://github.com/mitsuhiko/rust-sha1/issues/17) |  | :yellow_heart: |
| [SHA-2](https://en.wikipedia.org/wiki/SHA-2) |    | [![crates.io](https://img.shields.io/crates/v/sha2.svg)](https://crates.io/crates/sha2) |  [![Documentation](https://docs.rs/sha2/badge.svg)](https://docs.rs/sha2) | :green_heart: |
| [SHA-3](https://en.wikipedia.org/wiki/SHA-3) |  Keccak  | [![crates.io](https://img.shields.io/crates/v/sha3.svg)](https://crates.io/crates/sha3) |  [![Documentation](https://docs.rs/sha3/badge.svg)](https://docs.rs/sha3) | :green_heart: |
| [Streebog](https://en.wikipedia.org/wiki/Streebog) |  GOST R 34.11-2012  | [![crates.io](https://img.shields.io/crates/v/streebog.svg)](https://crates.io/crates/streebog) |  [![Documentation](https://docs.rs/streebog/badge.svg)](https://docs.rs/streebog) | :yellow_heart: |
| [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(cryptography)) |    | [![crates.io](https://img.shields.io/crates/v/whirlpool.svg)](https://crates.io/crates/whirlpool) |  [![Documentation](https://docs.rs/whirlpool/badge.svg)](https://docs.rs/whirlpool) | :yellow_heart: |

[Security Level]: https://en.wikipedia.org/wiki/Hash_function_security_summary

**Security Level Legend**

The following describes the security level ratings associated with each
hash function (i.e. algorithms, not the specific implementation):

| Heart | Description |
|-------|-------------|
| :green_heart: | No known successful attacks |
| :yellow_heart: | Theoretical break: security lower than claimed |
| :broken_heart: | Attack demonstrated in practice: avoid if at all possible |
