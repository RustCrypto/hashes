#![no_std]
#[macro_use]
extern crate digest;
extern crate sha3;

use digest::dev::{digest_test, xof_test};

new_test!(keccak_224, "keccak_224", sha3::Keccak224, digest_test);
new_test!(keccak_256, "keccak_256", sha3::Keccak256, digest_test);
new_test!(keccak_384, "keccak_384", sha3::Keccak384, digest_test);
new_test!(keccak_512, "keccak_512", sha3::Keccak512, digest_test);

new_test!(sha3_224, "sha3_224", sha3::Sha3_224, digest_test);
new_test!(sha3_256, "sha3_256", sha3::Sha3_256, digest_test);
new_test!(sha3_384, "sha3_384", sha3::Sha3_384, digest_test);
new_test!(sha3_512, "sha3_512", sha3::Sha3_512, digest_test);

new_test!(shake128_1, "shake128_1", sha3::Shake128, xof_test);
new_test!(shake128_2, "shake128_2", sha3::Shake128, xof_test);
new_test!(shake128_3, "shake128_3", sha3::Shake128, xof_test);
new_test!(shake256_1, "shake256_1", sha3::Shake256, xof_test);
new_test!(shake256_2, "shake256_2", sha3::Shake256, xof_test);
new_test!(shake256_3, "shake256_3", sha3::Shake256, xof_test);
