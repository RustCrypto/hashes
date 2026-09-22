#[cfg(not(feature = "reset"))]
mod serialization_tests {
    use crate::hash_mac_serialization_test;
    use digest::hash_serialization_test;

    hash_serialization_test!(blake2b_128_serialization, blake2::Blake2b128);
    hash_serialization_test!(blake2b_256_serialization, blake2::Blake2b256);
    hash_serialization_test!(blake2b_512_serialization, blake2::Blake2b512);
    hash_mac_serialization_test!(blake2b_mac_512_serialization, blake2::Blake2bMac512, 64);
    hash_serialization_test!(blake2s_128_serialization, blake2::Blake2s128);
    hash_serialization_test!(blake2s_256_serialization, blake2::Blake2s256);
    hash_mac_serialization_test!(blake2s_mac_256_serialization, blake2::Blake2sMac256, 32);
}

#[cfg(feature = "reset")]
mod serialization_tests {
    use crate::hash_mac_serialization_test;
    use digest::hash_serialization_test;

    hash_serialization_test!(blake2b_128_reset_serialization, blake2::Blake2b128);
    hash_serialization_test!(blake2b_256_reset_serialization, blake2::Blake2b256);
    hash_serialization_test!(blake2b_512_reset_serialization, blake2::Blake2b512);
    hash_mac_serialization_test!(
        blake2b_mac_512_reset_serialization,
        blake2::Blake2bMac512,
        64
    );
    hash_serialization_test!(blake2s_128_reset_serialization, blake2::Blake2s128);
    hash_serialization_test!(blake2s_256_reset_serialization, blake2::Blake2s256);
    hash_mac_serialization_test!(
        blake2s_mac_256_reset_serialization,
        blake2::Blake2sMac256,
        32
    );
}

#[macro_export]
macro_rules! hash_mac_serialization_test {
    ($name:ident, $hasher:ty, $keysize:literal $(,)?) => {
        #[test]
        fn $name() {
            use blake2::digest::KeyInit;
            use digest::{Mac, array::Array, common::hazmat::SerializableState, typenum::Unsigned};

            let mut h = <$hasher>::new(&Array::try_from(&[0x42u8; $keysize] as &[u8]).unwrap());

            // in absence of other sizes we can use as reference (BlockSizeUser can't be accessed
            // for blake2 Mac hashers), use the state size
            digest::Update::update(
                &mut h,
                &[0x13; <$hasher as SerializableState>::SerializedStateSize::USIZE + 1],
            );

            let serialized_state = h.serialize();
            let expected = include_bytes!(concat!("data/", stringify!($name), ".bin"));
            assert_eq!(serialized_state.as_slice(), expected);

            let mut h = <$hasher>::deserialize(&serialized_state).unwrap();

            digest::Update::update(
                &mut h,
                &[0x13; <$hasher as SerializableState>::SerializedStateSize::USIZE + 1],
            );
            let output1 = h.finalize();

            let mut h = <$hasher>::new(&Array::try_from(&[0x42u8; $keysize] as &[u8]).unwrap());
            digest::Update::update(
                &mut h,
                &[0x13; 2 * (<$hasher as SerializableState>::SerializedStateSize::USIZE + 1)],
            );
            let output2 = h.finalize();

            assert_eq!(output1, output2);
        }
    };
}

macro_rules! gen_test_file {
    ($name:ident) => {{
        use blake2::digest::typenum::Unsigned;
        use digest::Digest;
        use digest::common::{BlockSizeUser, hazmat::SerializableState};

        let mut a = blake2::$name::new();
        digest::Update::update(
            &mut a,
            &[0x13; <blake2::$name as BlockSizeUser>::BlockSize::USIZE + 1],
        );
        let serialized = a.serialize();
        let name = stringify!($name);
        std::fs::write(
            format!(
                "./tests/data/blake2{}_{}{}_serialization.bin",
                &name[6..7],
                &name[(name.len() - 3)..],
                (if cfg!(feature = "reset") {
                    "_reset"
                } else {
                    ""
                })
            ),
            serialized,
        )
        .unwrap();
    }};
}

macro_rules! gen_test_file_mac {
    ($name:ident, $keysize:literal) => {{
        use blake2::digest::{KeyInit, typenum::Unsigned};
        use digest::array::Array;
        use digest::common::hazmat::SerializableState;

        let mut a = blake2::$name::new(&Array::try_from(&[0x42u8; $keysize] as &[u8]).unwrap());
        digest::Update::update(
            &mut a,
            &[0x13; <blake2::$name as SerializableState>::SerializedStateSize::USIZE + 1],
        );
        let serialized = a.serialize();
        let name = stringify!($name);
        std::fs::write(
            format!(
                "./tests/data/blake2{}_mac_{}{}_serialization.bin",
                &name[6..7],
                &name[(name.len() - 3)..],
                (if cfg!(feature = "reset") {
                    "_reset"
                } else {
                    ""
                })
            ),
            serialized,
        )
        .unwrap();
    }};
}

/// Generates the data files used in the tests above. Remove #[ignore] to regenerate the data.
/// Needs to be executed twice, with feature="reset" enabled and disabled.
#[test]
#[ignore]
fn gen_test_files() {
    gen_test_file!(Blake2b128);
    gen_test_file!(Blake2b256);
    gen_test_file!(Blake2b512);
    gen_test_file_mac!(Blake2bMac512, 64);
    gen_test_file!(Blake2s128);
    gen_test_file!(Blake2s256);
    gen_test_file_mac!(Blake2sMac256, 32);
}
