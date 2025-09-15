use digest::dev::{fixed_reset_test, xof_reset_test};
use digest::new_test;

new_test!(sha3_224_kat, sha3::Sha3_224, fixed_reset_test);
new_test!(sha3_256_kat, sha3::Sha3_256, fixed_reset_test);
new_test!(sha3_384_kat, sha3::Sha3_384, fixed_reset_test);
new_test!(sha3_512_kat, sha3::Sha3_512, fixed_reset_test);

new_test!(shake128_kat, sha3::Shake128, xof_reset_test);
new_test!(shake256_kat, sha3::Shake256, xof_reset_test);

// Test vectors from https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171
new_test!(keccak_224_kat, sha3::Keccak224, fixed_reset_test);
new_test!(keccak_256_kat, sha3::Keccak256, fixed_reset_test);
new_test!(keccak_384_kat, sha3::Keccak384, fixed_reset_test);
new_test!(keccak_512_kat, sha3::Keccak512, fixed_reset_test);

new_test!(keccak_256_full_kat, sha3::Keccak256Full, fixed_reset_test);
