Assembly implementations of hash functions core functionality based on code from
[Project Nayuki](https://www.nayuki.io/).

Crates in this repository provide only core compression functions, for full hash
functionality please refer to the crates from
[RustCrypto/hashes](https://github.com/RustCrypto/hashes) repository. With
enabled `asm` feature `md5`, `sha-1`, `sha2` and `whirlpool` crates will use
code from this repository.