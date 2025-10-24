use bash_hash::{BashHash256, BashHash384, BashHash512};
use digest::Digest;
use digest::dev::fixed_reset_test;
use hex_literal::hex;

// Test vectors from STB 34.101.77-2020 (Appendix A, Table A.3)
digest::new_test!(bash256, BashHash256, fixed_reset_test);
digest::new_test!(bash384, BashHash384, fixed_reset_test);
digest::new_test!(bash512, BashHash512, fixed_reset_test);

macro_rules! test_bash_rand {
    ($name:ident, $hasher:ty, $expected:expr) => {
        #[test]
        fn $name() {
            let mut h = <$hasher>::new();
            digest::dev::feed_rand_16mib(&mut h);
            assert_eq!(h.finalize(), $expected);
        }
    };
}

test_bash_rand!(
    bash256_rand,
    BashHash256,
    hex!("03f23e09f2ab9ce3f228c21ab1861d2495fcaf81aae2d6bbefd525b95d0925d5")
);

test_bash_rand!(
    bash384_rand,
    BashHash384,
    hex!(
        "3a2932e47780b88aab04c33e0df3c9f53035e4e47daa89e5f8dddf43f4b21c20"
        "73d36887684245b87042661c0a3bb8ce"
    )
);

test_bash_rand!(
    bash512_rand,
    BashHash512,
    hex!(
        "f85aacf9fb6fe864d86604fb8d93485b533f29d874b49cd5521ad8afb1c11e8b"
        "710f8469b95c6af39147a132787801d194473d1bd7ce24fc23e97dc182bf8a9f"
    )
);

digest::hash_serialization_test!(bash256_serialization, BashHash256);
digest::hash_serialization_test!(bash384_serialization, BashHash384);
digest::hash_serialization_test!(bash512_serialization, BashHash512);
