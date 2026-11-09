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

#[test]
fn serialized_states_resume_at_every_rate_offset() {
    use digest::{Digest, common::hazmat::SerializableState};

    macro_rules! check {
        ($hasher:ty, $rate:expr) => {{
            let message = [0xa3; 2 * $rate + 1];
            let expected = <$hasher>::digest(message);
            for split in 0..=message.len() {
                let mut original = <$hasher>::new();
                original.update(&message[..split]);
                let state = original.serialize();
                let mut restored = <$hasher>::deserialize(&state).unwrap();
                restored.update(&message[split..]);
                assert_eq!(restored.finalize(), expected, "split {split}");
            }
            let mut state = <$hasher>::new().serialize();
            for cursor in ($rate as u8)..=u8::MAX {
                state[200] = cursor;
                assert!(<$hasher>::deserialize(&state).is_err(), "cursor {cursor}");
            }
        }};
    }

    check!(sha3::Sha3_224, 144);
    check!(sha3::Sha3_256, 136);
    check!(sha3::Sha3_384, 104);
    check!(sha3::Sha3_512, 72);
    check!(sha3::Keccak224, 144);
    check!(sha3::Keccak256, 136);
    check!(sha3::Keccak384, 104);
    check!(sha3::Keccak512, 72);
    check!(sha3::Keccak256Full, 136);
}
