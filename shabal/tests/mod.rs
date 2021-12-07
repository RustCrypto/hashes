#![no_std]

use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use hex_literal::hex;
use shabal::{Digest, Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};

new_test!(shabal192_main, "shabal192", Shabal192, fixed_reset_test);
new_test!(shabal224_main, "shabal224", Shabal224, fixed_reset_test);
new_test!(shabal256_main, "shabal256", Shabal256, fixed_reset_test);
new_test!(shabal384_main, "shabal384", Shabal384, fixed_reset_test);
new_test!(shabal512_main, "shabal512", Shabal512, fixed_reset_test);

#[test]
fn shabal192_rand() {
    let mut h = Shabal192::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("a3e480026be158db97976a895b7a015e9e5205986ebc8a89")[..]
    );
}

#[test]
fn shabal224_rand() {
    let mut h = Shabal224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("a09bedfed92fdffc896e6043ec175aa1f07383c65bde990a3661e3d0")[..]
    );
}

#[test]
fn shabal256_rand() {
    let mut h = Shabal256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("53252a6467450aa1afc1ac25efb493aa65b70e5b2280a4bed7f672c0cfe6f40e")[..]
    );
}

#[test]
#[rustfmt::skip]
fn shabal384_rand() {
    let mut h = Shabal384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            15b8ece81e490848c997dba603523be8842c654262e5adc29138d22a01ff0c9f
            2b0a0dc9f3e7702ac3598fb1b9ff2db2
        ")[..]
    );
}

#[test]
#[rustfmt::skip]
fn shabal512_rand() {
    let mut h = Shabal512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            66f091bc2ba6c571a776441c08ee0711752344ba8b4c88ea17a078baa70d8c0a
            717b7da24e765867cfcf273a43a58f90e07c0130d1e97adc49f66a0502536e82
        ")[..]
    );
}
