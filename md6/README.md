# RustCrypto: MD6

Pure Rust implementation of the MD6 hash function.

## Example

### Fixed output size

```rust
use md6::Md6_256;
use digest::Digest;
use hex_literal::hex;

// create a Md6_256 object
let mut hasher = Md6_256::new();

// write input message
hasher.update(b"hello world");

// read hash digest and consume hasher
let hash = hasher.finalize();
assert_eq!(hash[..], hex!(
    "9ae602639631cc2c60adaa7a952aae8756141f31a7e6a9b76adc1de121db2230"
));
```

Also, see the [examples section] in the RustCrypto/hashes readme.

### Variable output size

This implementation supports run and compile time variable sizes.

Output size set at run time:
```rust
use md6::Md6Var;
use digest::{Update, VariableOutput};
use hex_literal::hex;

let mut hasher = Md6Var::new(12).unwrap();
hasher.update(b"hello rust");
let mut buf = [0u8; 12];
hasher.finalize_variable(&mut buf).unwrap();
assert_eq!(buf, hex!("9c5b8d9744898ec981bcc573"));
```

Output size set at compile time:
```rust
use md6::Md6;
use digest::{Digest, consts::U20};
use hex_literal::hex;

type Md6_160 = Md6<U20>;

let mut hasher = Md6_160::new();
hasher.update(b"hello rust");
let res = hasher.finalize();
assert_eq!(res, hex!("576d736a93a555a1c868973cfdd2d21838a26623"));
```

## License

The crate is licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
