use digest::{
    dev::{feed_rand_16mib, fixed_reset_test},
    hash_serialization_test, new_test,
};
use hex_literal::hex;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

new_test!(sha224_kat, Sha224, fixed_reset_test);
new_test!(sha256_kat, Sha256, fixed_reset_test);
new_test!(sha384_kat, Sha384, fixed_reset_test);
new_test!(sha512_kat, Sha512, fixed_reset_test);
new_test!(sha512_224_kat, Sha512_224, fixed_reset_test);
new_test!(sha512_256_kat, Sha512_256, fixed_reset_test);

hash_serialization_test!(sha224_serialization, Sha224);
hash_serialization_test!(sha256_serialization, Sha256);
hash_serialization_test!(sha384_serialization, Sha384);
hash_serialization_test!(sha512_serialization, Sha512);
hash_serialization_test!(sha512_224_serialization, Sha512_224);
hash_serialization_test!(sha512_256_serialization, Sha512_256);

#[test]
fn sha256_rand() {
    let mut h = Sha256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("45f51fead87328fe837a86f4f1ac0eb15116ab1473adc0423ef86c62eb2320c7"),
    );
}

#[test]
fn sha512_rand() {
    let mut h = Sha512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "9084d75a7c0721541d737b6171eb465dc9ba08a119a182a8508484aa27a176cd"
            "e7c2103b108393eb024493ced4aac56be6f57222cac41b801f11494886264997"
        ),
    );
}

#[test]
fn sha512_serializable_state_is_stable() {
    use sha2::digest::common::hazmat::SerializableState;
    let mut h = Sha512::new();
    h.update("just a random example text");
    let state: &[u8] = &h.serialize();
    assert_eq!(
        state,
        [
            8, 201, 188, 243, 103, 230, 9, 106, 59, 167, 202, 132, 133, 174, 103, 187, 43, 248,
            148, 254, 114, 243, 110, 60, 241, 54, 29, 95, 58, 245, 79, 165, 209, 130, 230, 173,
            127, 82, 14, 81, 31, 108, 62, 43, 140, 104, 5, 155, 107, 189, 65, 251, 171, 217, 131,
            31, 121, 33, 126, 19, 25, 205, 224, 91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            26, 106, 117, 115, 116, 32, 97, 32, 114, 97, 110, 100, 111, 109, 32, 101, 120, 97, 109,
            112, 108, 101, 32, 116, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    let h = Sha512::deserialize(state.try_into().expect("state to be of correct length"))
        .expect("state to be deserialized");
    let digest: &[u8] = &h.finalize();
    assert_eq!(
        digest,
        [
            193, 156, 193, 73, 92, 41, 172, 27, 181, 186, 218, 80, 174, 96, 210, 30, 235, 136, 156,
            147, 88, 203, 90, 202, 9, 103, 158, 201, 133, 185, 63, 164, 60, 128, 240, 190, 211,
            151, 102, 19, 52, 169, 152, 70, 87, 22, 183, 67, 32, 99, 129, 240, 116, 246, 210, 141,
            238, 243, 135, 41, 115, 15, 166, 87
        ]
    );
}
