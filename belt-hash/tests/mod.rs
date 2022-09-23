use belt_hash::{BeltHash, Digest};
use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;

// Test vectors from STB 34.101.31-2020 (Section A.11, Table A.23):
// http://apmi.bsu.by/assets/files/std/belt-spec371.pdf
digest::new_test!(belt_stb, "stb", BeltHash, fixed_reset_test);

#[test]
fn belt_rand() {
    let mut h = BeltHash::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!(
            "a45053f80827d530008198c8185aa507"
            "403b4a21f591579f07c34358e5991754"
        )[..]
    );
}
