# RustCrypto: Hashes

[![Project Chat][chat-image]][chat-link] [![dependency status][deps-image]][deps-link] ![Apache2/MIT licensed][license-image]

Collection of [cryptographic hash functions][1] written in pure Rust.

All algorithms reside in separate crates and are implemented using traits from [`digest`] crate.
Additionally all crates do not require the standard library (i.e. `no_std` capable) and can be easily used for bare-metal or WebAssembly programming.

## Supported Algorithms

**Note:** For new applications, or where compatibility with other existing standards is not a primary concern, we strongly recommend to use either BLAKE2, SHA-2 or SHA-3.

| Algorithm | Crate | Crates.io | Documentation | MSRV | [Security] |
|-----------|-------|:---------:|:-------------:|:----:|:----------:|
| [Ascon] hash | [`ascon‑hash`] | [![crates.io](https://img.shields.io/crates/v/ascon-hash.svg)](https://crates.io/crates/ascon-hash) | [![Documentation](https://docs.rs/ascon-hash/badge.svg)](https://docs.rs/ascon-hash) | ![MSRV 1.56][msrv-1.56] | :green_heart: |
| [BelT] hash | [`belt‑hash`] | [![crates.io](https://img.shields.io/crates/v/belt-hash.svg)](https://crates.io/crates/belt-hash) | [![Documentation](https://docs.rs/belt-hash/badge.svg)](https://docs.rs/belt-hash) | ![MSRV 1.57][msrv-1.57] | :green_heart: |
| [BLAKE2] | [`blake2`] | [![crates.io](https://img.shields.io/crates/v/blake2.svg)](https://crates.io/crates/blake2) | [![Documentation](https://docs.rs/blake2/badge.svg)](https://docs.rs/blake2) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [FSB] | [`fsb`] | [![crates.io](https://img.shields.io/crates/v/fsb.svg)](https://crates.io/crates/fsb) | [![Documentation](https://docs.rs/fsb/badge.svg)](https://docs.rs/fsb) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [GOST R 34.11-94][GOST94] | [`gost94`] | [![crates.io](https://img.shields.io/crates/v/gost94.svg)](https://crates.io/crates/gost94) | [![Documentation](https://docs.rs/gost94/badge.svg)](https://docs.rs/gost94) | ![MSRV 1.41][msrv-1.41] | :yellow_heart: |
| [Grøstl] (Groestl) | [`groestl`] | [![crates.io](https://img.shields.io/crates/v/groestl.svg)](https://crates.io/crates/groestl) | [![Documentation](https://docs.rs/groestl/badge.svg)](https://docs.rs/groestl) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [JH] | [`jh`] | [![crates.io](https://img.shields.io/crates/v/jh.svg)](https://crates.io/crates/jh) | [![Documentation](https://docs.rs/jh/badge.svg)](https://docs.rs/jh) | ![MSRV 1.57][msrv-1.57] | :green_heart: |
| [KangarooTwelve] | [`k12`] | [![crates.io](https://img.shields.io/crates/v/k12.svg)](https://crates.io/crates/k12) | [![Documentation](https://docs.rs/k12/badge.svg)](https://docs.rs/k12) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [MD2] | [`md2`] | [![crates.io](https://img.shields.io/crates/v/md2.svg)](https://crates.io/crates/md2) | [![Documentation](https://docs.rs/md2/badge.svg)](https://docs.rs/md2) | ![MSRV 1.41][msrv-1.41] | :broken_heart: |
| [MD4] | [`md4`] | [![crates.io](https://img.shields.io/crates/v/md4.svg)](https://crates.io/crates/md4) | [![Documentation](https://docs.rs/md4/badge.svg)](https://docs.rs/md4) | ![MSRV 1.41][msrv-1.41] | :broken_heart: |
| [MD5] | [`md5`] [:exclamation:] | [![crates.io](https://img.shields.io/crates/v/md-5.svg)](https://crates.io/crates/md-5) | [![Documentation](https://docs.rs/md-5/badge.svg)](https://docs.rs/md-5) | ![MSRV 1.41][msrv-1.41] | :broken_heart: |
| [RIPEMD] | [`ripemd`] | [![crates.io](https://img.shields.io/crates/v/ripemd.svg)](https://crates.io/crates/ripemd) | [![Documentation](https://docs.rs/ripemd/badge.svg)](https://docs.rs/ripemd) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [SHA-1] | [`sha1`] | [![crates.io](https://img.shields.io/crates/v/sha1.svg)](https://crates.io/crates/sha1) | [![Documentation](https://docs.rs/sha1/badge.svg)](https://docs.rs/sha1) | ![MSRV 1.41][msrv-1.41] | :broken_heart: |
| [SHA-2] | [`sha2`] | [![crates.io](https://img.shields.io/crates/v/sha2.svg)](https://crates.io/crates/sha2) | [![Documentation](https://docs.rs/sha2/badge.svg)](https://docs.rs/sha2) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [SHA-3] (Keccak) | [`sha3`] | [![crates.io](https://img.shields.io/crates/v/sha3.svg)](https://crates.io/crates/sha3) | [![Documentation](https://docs.rs/sha3/badge.svg)](https://docs.rs/sha3) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [SHABAL] | [`shabal`] | [![crates.io](https://img.shields.io/crates/v/shabal.svg)](https://crates.io/crates/shabal) | [![Documentation](https://docs.rs/shabal/badge.svg)](https://docs.rs/shabal) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [Skein] | [`skein`] | [![crates.io](https://img.shields.io/crates/v/skein.svg)](https://crates.io/crates/skein) | [![Documentation](https://docs.rs/skein/badge.svg)](https://docs.rs/skein) | ![MSRV 1.57][msrv-1.57] | :green_heart: |
| [SM3] (OSCCA GM/T 0004-2012) | [`sm3`] | [![crates.io](https://img.shields.io/crates/v/sm3.svg)](https://crates.io/crates/sm3) | [![Documentation](https://docs.rs/sm3/badge.svg)](https://docs.rs/sm3) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [Streebog] (GOST R 34.11-2012) | [`streebog`] | [![crates.io](https://img.shields.io/crates/v/streebog.svg)](https://crates.io/crates/streebog) | [![Documentation](https://docs.rs/streebog/badge.svg)](https://docs.rs/streebog) | ![MSRV 1.41][msrv-1.41] | :yellow_heart: |
| [Tiger] | [`tiger`] | [![crates.io](https://img.shields.io/crates/v/tiger.svg)](https://crates.io/crates/tiger) | [![Documentation](https://docs.rs/tiger/badge.svg)](https://docs.rs/tiger) | ![MSRV 1.41][msrv-1.41] | :green_heart: |
| [Whirlpool] | [`whirlpool`] | [![crates.io](https://img.shields.io/crates/v/whirlpool.svg)](https://crates.io/crates/whirlpool) | [![Documentation](https://docs.rs/whirlpool/badge.svg)](https://docs.rs/whirlpool) | ![MSRV 1.41][msrv-1.41] | :green_heart: |

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

The SHA-1 implementation was previously published as `sha-1`, but migrated to `sha1` since v0.10.0.
`sha-1` will continue to receive v0.10.x patch updates, but will be deprecated after `sha1` v0.11 release.

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## Usage

Let us demonstrate how to use crates in this repository using SHA-2 as an example.

First add [`sha2`](https://docs.rs/sha2) crate to your `Cargo.toml`:

```toml
[dependencies]
sha2 = "0.10"
```

Note that all crates in this repository have an enabled by default `std` feature.
So if you plan to use the crate in `no_std` environments, don't forget to disable it:

```toml
[dependencies]
sha2 = { version = "0.10", default-features = false }
```

[`sha2`](https://docs.rs/sha2) and the other hash implementation crates re-export the [`digest`] crate and the [`Digest`] trait for convenience, so you don't have to include it in your `Cargo.toml` it as an explicit dependency.

Now you can write the following code:

```rust
use sha2::{Sha256, Digest};

let mut hasher = Sha256::new();
let data = b"Hello world!";
hasher.update(data);
// `update` can be called repeatedly and is generic over `AsRef<[u8]>`
hasher.update("String data");
// Note that calling `finalize()` consumes hasher
let hash = hasher.finalize();
println!("Binary hash: {:?}", hash);
```

In this example `hash` has type `GenericArray<u8, U32>`, which is a generic alternative to `[u8; 32]` defined in the [`generic-array`] crate.
If you need to serialize hash value into string, you can use crates like [`base16ct`] and [`base64ct`]:
```rust
use base64ct::{Base64, Encoding};

let base64_hash = Base64::encode_string(&hash);
println!("Base64-encoded hash: {}", base64_hash);

let hex_hash = base16ct::lower::encode_string(&hash);
println!("Hex-encoded hash: {}", hex_hash);
```

Instead of calling `update`, you also can use a chained approach:

```rust
use sha2::{Sha256, Digest};

let hash = Sha256::new()
    .chain_update(b"Hello world!")
    .chain_update("String data")
    .finalize();
```

If a complete message is available, then you can use the convenience [`Digest::digest`] method:

```rust
use sha2::{Sha256, Digest};

let hash = Sha256::digest(b"my message");
```

### Hashing `Read`able Objects

If you want to hash data from a type which implements the [`Read`] trait, you can rely on implementation of the [`Write`] trait (requires enabled-by-default `std` feature):

```rust
use sha2::{Sha256, Digest};
use std::{fs, io};

let mut file = fs::File::open(&path)?;
let mut hasher = Sha256::new();
let n = io::copy(&mut file, &mut hasher)?;
let hash = hasher.finalize();
```

### Hash-based Message Authentication Code (HMAC)

If you want to calculate [Hash-based Message Authentication Code][HMAC] (HMAC), you can use the generic implementation from [`hmac`] crate, which is a part of the [RustCrypto/MACs] repository.

### Generic Code

You can write generic code over the [`Digest`] trait (or other traits from the [`digest`] crate) which will work over different hash functions:

```rust
use sha2::{Sha256, Sha512, Digest};

// Toy example, do not use it in practice!
// Instead use crates from: https://github.com/RustCrypto/password-hashing
fn hash_password<D: Digest>(password: &str, salt: &str, output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(password.as_bytes());
    hasher.update(b"$");
    hasher.update(salt.as_bytes());
    output.copy_from_slice(&hasher.finalize())
}

let mut buf1 = [0u8; 32];
hash_password::<Sha256>("my_password", "abcd", &mut buf1);

let mut buf2 = [0u8; 64];
hash_password::<Sha512>("my_password", "abcd", &mut buf2);
```

If you want to use hash functions with trait objects, you can use the [`DynDigest`] trait:

```rust
use digest::DynDigest;

// Dynamic hash function
fn use_hasher(hasher: &mut dyn DynDigest, data: &[u8]) -> Box<[u8]> {
    hasher.update(data);
    hasher.finalize_reset()
}

// You can use something like this when parsing user input, CLI arguments, etc.
// DynDigest needs to be boxed here, since function return should be sized.
fn select_hasher(s: &str) -> Box<dyn DynDigest> {
    match s {
        "md5" => Box::new(md5::Md5::default()),
        "sha1" => Box::new(sha1::Sha1::default()),
        "sha224" => Box::new(sha2::Sha224::default()),
        "sha256" => Box::new(sha2::Sha256::default()),
        "sha384" => Box::new(sha2::Sha384::default()),
        "sha512" => Box::new(sha2::Sha512::default()),
        _ => unimplemented!("unsupported digest: {}", s),
    }
}

let mut hasher1 = select_hasher("md5");
let mut hasher2 = select_hasher("sha512");

// the `&mut *hasher` is to DerefMut the value out of the Box
// this is equivalent to `DerefMut::deref_mut(&mut hasher)`

// can be reused due to `finalize_reset()`
let hash1_1 = use_hasher(&mut *hasher1, b"foo");
let hash1_2 = use_hasher(&mut *hasher1, b"bar");
let hash2_1 = use_hasher(&mut *hasher2, b"foo");
```

## License

All crates licensed under either of

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
[msrv-1.41]: https://img.shields.io/badge/rustc-1.41.0+-blue.svg
[msrv-1.56]: https://img.shields.io/badge/rustc-1.56.0+-blue.svg
[msrv-1.57]: https://img.shields.io/badge/rustc-1.57.0+-blue.svg

[//]: # (crates)

[`ascon‑hash`]: ./ascon-hash
[`belt‑hash`]: ./belt-hash
[`blake2`]: ./blake2
[`fsb`]: ./fsb
[`gost94`]: ./gost94
[`groestl`]: ./groestl
[`jh`]: ./jh
[`k12`]: ./k12
[`md2`]: ./md2
[`md4`]: ./md4
[`md5`]: ./md5
[`ripemd`]: ./ripemd
[`sha1`]: ./sha1
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
[BelT]: https://ru.wikipedia.org/wiki/BelT
[BLAKE2]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
[FSB]: https://en.wikipedia.org/wiki/Fast_syndrome-based_hash
[GOST94]: https://en.wikipedia.org/wiki/GOST_(hash_function)
[Grøstl]: https://en.wikipedia.org/wiki/Grøstl
[JH]: https://www3.ntu.edu.sg/home/wuhj/research/jh
[KangarooTwelve]: https://keccak.team/kangarootwelve.html
[MD2]: https://en.wikipedia.org/wiki/MD2_(cryptography)
[MD4]: https://en.wikipedia.org/wiki/MD4
[MD5]: https://en.wikipedia.org/wiki/MD5
[RIPEMD]: https://en.wikipedia.org/wiki/RIPEMD
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[SHA-2]: https://en.wikipedia.org/wiki/SHA-2
[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[SHABAL]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
[Skein]: https://schneier.com/academic/skein
[SM3]: https://en.wikipedia.org/wiki/SM3_(hash_function)
[Streebog]: https://en.wikipedia.org/wiki/Streebog
[Whirlpool]: https://en.wikipedia.org/wiki/Whirlpool_(cryptography)
[Tiger]: http://www.cs.technion.ac.il/~biham/Reports/Tiger/tiger/tiger.html
