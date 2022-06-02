use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use fsb::{Digest, Fsb160, Fsb224, Fsb256, Fsb384, Fsb512};
use hex_literal::hex;

new_test!(fsb160_main, "fsb160", Fsb160, fixed_reset_test);
new_test!(fsb224_main, "fsb224", Fsb224, fixed_reset_test);
new_test!(fsb256_main, "fsb256", Fsb256, fixed_reset_test);
new_test!(fsb384_main, "fsb384", Fsb384, fixed_reset_test);
new_test!(fsb512_main, "fsb512", Fsb512, fixed_reset_test);

#[test]
fn fsb160_rand() {
    let mut h = Fsb160::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("40b7538be5e51978690d1a92fe12a7f25f0a7f08")[..]
    );
}

#[test]
fn fsb224_rand() {
    let mut h = Fsb224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("0ec203ccec7cbf0cadd32e5dc069d0b4215a104c4dad5444944a0d09")[..]
    );
}

#[test]
fn fsb256_rand() {
    let mut h = Fsb256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("eecb42832a2b03bc91beb1a56ddf2973c962b1aeb22f278e9d78a7a8879ebba7")[..]
    );
}

#[test]
#[rustfmt::skip]
fn fsb384_rand() {
    let mut h = Fsb384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            f17533ed4d4484434715e63bc8e801c9cfe988c38d47d3b4be0409571360aa2f
            b360b2804c14f606906b323e7901c09e
        ")[..]
    );
}

#[test]
#[rustfmt::skip]
fn fsb512_rand() {
    let mut h = Fsb512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            957a7733643e075ab7a3b04607800a6208a26b008bdaee759a3a635bb9b5b708
            3531725783505468bf438f2a0a96163bbe0775468a11c93db9994c466b2e7d8c
        ")[..]
    );
}
