# RustCrypto: hashes

Collection of [cryptographic hash functions][1] written in pure Rust.

All algorithms reside in the separate crates and implemented using traits from
[`digest`](https://docs.rs/digest/) crate. Additionally all crates do not
require the standard library (i.e. `no_std` capable) and can be easily used for
bare-metal or WebAssembly programming.

## Supported algorithms
**Note:** For new applications, or where compatibility with other existing
standards is not a primary concern, we strongly recommend to use either
BLAKE2, SHA-2 or SHA-3.

| Name        | Algorithm  | Crates.io | Documentation | Build Status | [Security] |
|-------------|------------|-----------|---------------|--------------|------------|
| `blake2`    | [BLAKE2] | [![crates.io](https://img.shields.io/crates/v/blake2.svg)](https://crates.io/crates/blake2) | [![Documentation](https://docs.rs/blake2/badge.svg)](https://docs.rs/blake2) | ![build](https://github.com/rustcrypto/hashes/workflows/blake2/badge.svg?branch=master&event=push) | :green_heart: |
| `gost94`    | [GOST94] (GOST R 34.11-94) | [![crates.io](https://img.shields.io/crates/v/gost94.svg)](https://crates.io/crates/gost94) | [![Documentation](https://docs.rs/gost94/badge.svg)](https://docs.rs/gost94) | ![build](https://github.com/rustcrypto/hashes/workflows/gost94/badge.svg?branch=master&event=push) | :yellow_heart: |
| `groestl`   | [Grøstl] (Groestl) | [![crates.io](https://img.shields.io/crates/v/groestl.svg)](https://crates.io/crates/groestl) | [![Documentation](https://docs.rs/groestl/badge.svg)](https://docs.rs/groestl) | ![build](https://github.com/rustcrypto/hashes/workflows/groestl/badge.svg?branch=master&event=push) | :green_heart: |
| `k12`       | [KangarooTwelve] | [![crates.io](https://img.shields.io/crates/v/k12.svg)](https://crates.io/crates/k12) | [![Documentation](https://docs.rs/k12/badge.svg)](https://docs.rs/k12) | ![build](https://github.com/rustcrypto/hashes/workflows/k12/badge.svg?branch=master&event=push) | :green_heart: |
| `md2`       | [MD2] | [![crates.io](https://img.shields.io/crates/v/md2.svg)](https://crates.io/crates/md2) |  [![Documentation](https://docs.rs/md2/badge.svg)](https://docs.rs/md2) | ![build](https://github.com/rustcrypto/hashes/workflows/md2/badge.svg?branch=master&event=push) | :broken_heart: |
| `md4`       | [MD4] | [![crates.io](https://img.shields.io/crates/v/md4.svg)](https://crates.io/crates/md4) |  [![Documentation](https://docs.rs/md4/badge.svg)](https://docs.rs/md4) | ![build](https://github.com/rustcrypto/hashes/workflows/md4/badge.svg?branch=master&event=push) | :broken_heart: |
| `md-5` [:exclamation:] | [MD5]  | [![crates.io](https://img.shields.io/crates/v/md-5.svg)](https://crates.io/crates/md-5) | [![Documentation](https://docs.rs/md-5/badge.svg)](https://docs.rs/md-5) | ![build](https://github.com/rustcrypto/hashes/workflows/md5/badge.svg?branch=master&event=push) | :broken_heart: |
| `ripemd160` | [RIPEMD-160] | [![crates.io](https://img.shields.io/crates/v/ripemd160.svg)](https://crates.io/crates/ripemd160) |  [![Documentation](https://docs.rs/ripemd160/badge.svg)](https://docs.rs/ripemd160) | ![build](https://github.com/rustcrypto/hashes/workflows/ripemd160/badge.svg?branch=master&event=push) | :green_heart: |
| `ripemd320` | [RIPEMD-320] | [![crates.io](https://img.shields.io/crates/v/ripemd320.svg)](https://crates.io/crates/ripemd320) |  [![Documentation](https://docs.rs/ripemd320/badge.svg)](https://docs.rs/ripemd320) | ![build](https://github.com/rustcrypto/hashes/workflows/ripemd320/badge.svg?branch=master&event=push) | :green_heart:* |
| `sha-1` [:exclamation:] | [SHA-1] | [![crates.io](https://img.shields.io/crates/v/sha-1.svg)](https://crates.io/crates/sha-1) | [![Documentation](https://docs.rs/sha-1/badge.svg)](https://docs.rs/sha-1) | ![build](https://github.com/rustcrypto/hashes/workflows/sha1/badge.svg?branch=master&event=push) | :broken_heart: |
| `sha2`      | [SHA-2] | [![crates.io](https://img.shields.io/crates/v/sha2.svg)](https://crates.io/crates/sha2) |  [![Documentation](https://docs.rs/sha2/badge.svg)](https://docs.rs/sha2) | ![build](https://github.com/rustcrypto/hashes/workflows/sha2/badge.svg?branch=master&event=push) | :green_heart: |
| `sha3`      | [SHA-3] (Keccak) | [![crates.io](https://img.shields.io/crates/v/sha3.svg)](https://crates.io/crates/sha3) |  [![Documentation](https://docs.rs/sha3/badge.svg)](https://docs.rs/sha3) | ![build](https://github.com/rustcrypto/hashes/workflows/sha3/badge.svg?branch=master&event=push) | :green_heart: |
| `shabal`    | [SHABAL] | [![crates.io](https://img.shields.io/crates/v/shabal.svg)](https://crates.io/crates/shabal) |  [![Documentation](https://docs.rs/shabal/badge.svg)](https://docs.rs/shabal) | ![build](https://github.com/rustcrypto/hashes/workflows/shabal/badge.svg?branch=master&event=push) | :green_heart: |
| `streebog`  | [Streebog] (GOST R 34.11-2012) | [![crates.io](https://img.shields.io/crates/v/streebog.svg)](https://crates.io/crates/streebog) |  [![Documentation](https://docs.rs/streebog/badge.svg)](https://docs.rs/streebog) | ![build](https://github.com/rustcrypto/hashes/workflows/streebog/badge.svg?branch=master&event=push) | :yellow_heart: |
| `whirlpool` | [Whirlpool] | [![crates.io](https://img.shields.io/crates/v/whirlpool.svg)](https://crates.io/crates/whirlpool) |  [![Documentation](https://docs.rs/whirlpool/badge.svg)](https://docs.rs/whirlpool) | ![build](https://github.com/rustcrypto/hashes/workflows/whirlpool/badge.svg?branch=master&event=push) | :green_heart: |

NOTE: the [BLAKE3 crate](https://github.com/BLAKE3-team/BLAKE3) implements the `digest` (and `crypto-mac`) traits used by the rest of the hashes in this repository, but is maintained by the BLAKE3 team.

\* RIPEMD-320 provides only the same security as RIPEMD-160

[Security]: https://en.wikipedia.org/wiki/Hash_function_security_summary
[:exclamation:]: #crate-names

### Crate names
Whenever possible crates are published under the the same name as the crate
folder. Owners of `md5` and `sha1` crates declined
([1](https://github.com/stainless-steel/md5/pull/2),
[2](https://github.com/mitsuhiko/rust-sha1/issues/17)) to participate in this
project. This is why crates marked by :exclamation: are published under
`md-5` and `sha-1` names respectively.

### Security Level Legend
The following describes the security level ratings associated with each
hash function (i.e. algorithms, not the specific implementation):

| Heart          | Description |
|----------------|-------------|
| :green_heart:  | No known successful attacks |
| :yellow_heart: | Theoretical break: security lower than claimed |
| :broken_heart: | Attack demonstrated in practice: avoid if at all possible |

See the [Security] page on Wikipedia for more information.

### Minimum Supported Rust Version (MSRV)
All crates in this repository support Rust 1.21 or higher. In future
minimally supported version of Rust can be changed, but it will be done with
a minor version bump.

## Usage
Let us demonstrate how to use crates in this repository using BLAKE2b as an
example.

First add `blake2` crate to your `Cargo.toml`:

```toml
[dependencies]
blake2 = "0.8"
```

Note that crates in this repository have an enabled by default `std` feature.
So if you plan to use the crate in `no_std` enviroments, don't forget to disable it:

```toml
[dependencies]
blake2 = { version="0.8", default-features = false }
```

`blake2` and other crates re-export `digest` crate and `Digest` trait for
convenience, so you don't have to add `digest` crate as an explicit dependency.

Now you can write the following code:

```Rust
use blake2::{Blake2b, Digest};

let mut hasher = Blake2b::new();
let data = b"Hello world!";
hasher.input(data);
// `input` can be called repeatedly and is generic over `AsRef<[u8]>`
hasher.input("String data");
// Note that calling `result()` consumes hasher
let hash = hasher.result();
println!("Result: {:x}", hash);
```

In this example `hash` has type [`GenericArray<u8, U64>`][2], which is a generic
alternative to `[u8; 64]`.

Alternatively you can use chained approach, which is equivalent to the previous
example:

```Rust
let hash = Blake2b::new()
    .chain(b"Hello world!")
    .chain("String data")
    .result();
println!("Result: {:x}", hash);
```

If the whole message is available you also can use convinience `digest` method:

```Rust
let hash = Blake2b::digest(b"my message");
println!("Result: {:x}", hash);
```

### Hashing `Read`able objects

If you want to hash data from [`Read`][3] trait (e.g. from file) you can rely on
implementation of [`Write`][4] trait (requires enabled-by-default `std` feature):

```Rust
use blake2::{Blake2b, Digest};
use std::{fs, io};

let mut file = fs::File::open(&path)?;
let mut hasher = Blake2b::new();
let n = io::copy(&mut file, &mut hasher)?;
let hash = hasher.result();
println!("Path: {}", path);
println!("Bytes processed: {}", n);
println!("Hash value: {:x}", hash);
```

### Hash-based Message Authentication Code (HMAC)

If you want to calculate [Hash-based Message Authentication Code][5] (HMAC),
you can use generic implementation from [`hmac`](https://docs.rs/hmac) crate,
which is a part of the [RustCrypto/MACs][6] repository.

### Generic code

You can write generic code over `Digest` (or other traits from `digest` crate)
trait which will work over different hash functions:

```Rust
use digest::Digest;

// Toy example, do not use it in practice!
// Instead use crates from: https://github.com/RustCrypto/password-hashing
fn hash_password<D: Digest>(password: &str, salt: &str, output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.input(password.as_bytes());
    hasher.input(b"$");
    hasher.input(salt.as_bytes());
    output.copy_from_slice(hasher.result().as_slice())
}

use blake2::Blake2b;
use sha2::Sha256;

hash_password::<Blake2b>("my_password", "abcd", &mut buf);
hash_password::<Sha256>("my_password", "abcd", &mut buf);
```

If you want to use hash functions with trait objects, use `digest::DynDigest`
trait.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (footnotes)

[1]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
[2]: https://docs.rs/generic-array
[3]: https://doc.rust-lang.org/std/io/trait.Read.html
[4]: https://doc.rust-lang.org/std/io/trait.Write.html
[5]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[6]: https://github.com/RustCrypto/MACs

[//]: # (algorithms)

[BLAKE2]: https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2
[GOST94]: https://en.wikipedia.org/wiki/GOST_(hash_function)
[Grøstl]: https://en.wikipedia.org/wiki/Grøstl
[KangarooTwelve]: https://keccak.team/kangarootwelve.html
[MD2]: https://en.wikipedia.org/wiki/MD2_(cryptography)
[MD4]: https://en.wikipedia.org/wiki/MD4
[MD5]: https://en.wikipedia.org/wiki/MD5
[RIPEMD-160]: https://en.wikipedia.org/wiki/RIPEMD
[RIPEMD-320]: https://en.wikipedia.org/wiki/RIPEMD
[SHA-1]: https://en.wikipedia.org/wiki/SHA-1
[SHA-2]: https://en.wikipedia.org/wiki/SHA-2
[SHA-3]: https://en.wikipedia.org/wiki/SHA-3
[SHABAL]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
[Streebog]: https://en.wikipedia.org/wiki/Streebog
[Whirlpool]: https://en.wikipedia.org/wiki/Whirlpool_(cryptography)
