use digest::hash_serialization_test;

hash_serialization_test!(keccak_224_serialization, sha3::Keccak224);
hash_serialization_test!(keccak_256_serialization, sha3::Keccak256);
hash_serialization_test!(keccak_384_serialization, sha3::Keccak384);
hash_serialization_test!(keccak_512_serialization, sha3::Keccak512);
hash_serialization_test!(keccak_256_full_serialization, sha3::Keccak256Full);
hash_serialization_test!(sha3_224_serialization, sha3::Sha3_224);
hash_serialization_test!(sha3_256_serialization, sha3::Sha3_256);
hash_serialization_test!(sha3_384_serialization, sha3::Sha3_384);
hash_serialization_test!(sha3_512_serialization, sha3::Sha3_512);
