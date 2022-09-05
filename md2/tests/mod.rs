use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use md2::{Digest, Md2};

digest::new_test!(md2_main, "md2", Md2, fixed_reset_test);

#[test]
fn md2_rand() {
    let mut h = Md2::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("f9638c7be725f4d0b5ac342560af1a5b")[..]
    );
}

#[rustfmt::skip]
digest::hash_serialization_test!(
    md2_serialization,
    Md2,
    hex!("
        30a6b6fb5560099020a61f1535a51a4b
        228e7e945ef919b6c670486ffde72dd6
        764728b6ce8222562c9ceae0cbbdaf01
        f3f2ef9fe6ed831b3de51fec14010573
        01130000000000000000000000000000
        00
    ")
);
