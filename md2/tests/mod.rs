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
