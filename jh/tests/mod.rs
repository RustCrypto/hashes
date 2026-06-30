use digest::{
    Digest,
    dev::{feed_rand_16mib, fixed_test},
    hash_serialization_test, new_test,
};
use hex_literal::hex;

new_test!(jh224_long_kat, jh::Jh224, fixed_test);
new_test!(jh256_long_kat, jh::Jh256, fixed_test);
new_test!(jh384_long_kat, jh::Jh384, fixed_test);
new_test!(jh512_long_kat, jh::Jh512, fixed_test);

new_test!(jh224_short_kat, jh::Jh224, fixed_test);
new_test!(jh256_short_kat, jh::Jh256, fixed_test);
new_test!(jh384_short_kat, jh::Jh384, fixed_test);
new_test!(jh512_short_kat, jh::Jh512, fixed_test);

hash_serialization_test!(jh224_serialization, jh::Jh224);
hash_serialization_test!(jh256_serialization, jh::Jh256);
hash_serialization_test!(jh384_serialization, jh::Jh384);
hash_serialization_test!(jh512_serialization, jh::Jh512);

macro_rules! test_jh_rand {
    ($name:ident, $hasher:ty, $expected:expr) => {
        #[test]
        fn $name() {
            let mut h = <$hasher>::new();
            feed_rand_16mib(&mut h);
            assert_eq!(&h.finalize()[..], &$expected[..]);
        }
    };
}

test_jh_rand!(
    jh224_rand,
    jh::Jh224,
    hex!("7a4e35b939ccbf71d7bc8243e87871d0891a845d09197ac4a0bc3af1")
);

test_jh_rand!(
    jh256_rand,
    jh::Jh256,
    hex!("553d2d32bea1224d56e59df45d07f8b464535154e702119d90a23510d7489f5e")
);

test_jh_rand!(
    jh384_rand,
    jh::Jh384,
    hex!(
        "ba049c6c00f8ef651861db921588b41d8d6ce3faf94c2ffb1bdbf91cefcac6d2"
        "f5d5510cb1b3e94ba529fb6a9e29a8e5"
    )
);

test_jh_rand!(
    jh512_rand,
    jh::Jh512,
    hex!(
        "692b44c9fa2c3982060c85cbcdfde6015ade526ef6aad5218ed8d1cdcb42f389"
        "6e21a345db74c83faa042ef4f996cf5e8478dcd3f03b87025bd3edc78beab126"
    )
);
