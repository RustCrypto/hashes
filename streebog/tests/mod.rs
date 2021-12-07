use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use hex_literal::hex;
use streebog::{Digest, Streebog256, Streebog512};

// Test vectors from:
// https://github.com/gost-engine/engine/tree/master/etalon
new_test!(
    streebog256_main,
    "streebog256",
    Streebog256,
    fixed_reset_test,
);
new_test!(
    streebog512_main,
    "streebog512",
    Streebog512,
    fixed_reset_test,
);

/// Test vectors from:
/// https://github.com/gost-engine/engine/blob/master/test/01-digest.t
#[test]
#[rustfmt::skip]
fn gost_engine_tests() {
    let h256 = &mut streebog::Streebog256::new();
    let h512 = &mut streebog::Streebog512::new();

    fn update(h256: &mut Streebog256, h512: &mut Streebog512, m: &[u8]) {
        h256.update(m);
        h512.update(m);
    }
    fn check(h256: &mut Streebog256, h512: &mut Streebog512, r256: [u8; 32], r512: [u8; 64]) {
        assert_eq!(h256.finalize_reset().as_slice(), &r256[..]);
        assert_eq!(h512.finalize_reset().as_slice(), &r512[..]);
    }

    for _ in 0..128 {
        update(h256, h512, b"12345670");
    }
    check(
        h256, h512,
        hex!("1906512b86a1283c68cec8419e57113efc562a1d0e95d8f4809542900c416fe4"),
        hex!("
            283587e434864d0d4bea97c0fb10e2dd421572fc859304bdf6a94673d652c590
            49212bad7802b4fcf5eecc1f8fab569d60f2c20dbd789a7fe4efbd79d8137ee7
        "),
    );

    for _ in 0..128 {
        update(h256, h512, &hex!("0001021584674531"));
    }
    check(
        h256, h512,
        hex!("2eb1306be3e490f18ff0e2571a077b3831c815c46c7d4fdf9e0e26de4032b3f3"),
        hex!("
            55656e5bcf795b499031a7833cd7dc18fe10d4a47e15be545c6ab3f304a4fe41
            1c4c39de5b1fc6844880111441e0b92bf1ec2fb7840453fe39a2b70ced461968
        "),
    );

    let mut buf = Vec::new();
    for _ in 0..128 {
        buf.extend_from_slice(b"12345670");
    }
    update(h256, h512, &buf[0..539]);
    check(
        h256, h512,
        hex!("c98a17f9fadff78d08521e4179a7b2e6275f3b1da88339a3cb961a3514e5332e"),
        hex!("
            d5ad93fbc9ed7abc1cf28d00827a052b40bea74b04c4fd753102c1bcf9f9dad5
            142887f8a4cceaa0d64a0a8291592413d6adb956b99138a0023e127ff37bdf08
        "),
    );

    for _ in 0..4096 {
        for _ in 0..7 {
            update(h256, h512, b"121345678");
        }
        update(h256, h512, b"1234567\n");
    }
    update(h256, h512, b"12345\n");
    check(
        h256, h512,
        hex!("50e935d725d9359e5991b6b7eba8b3539fca03584d26adf4c827c982ffd49367"),
        hex!("
            1d93645ebfbb477660f98b7d1598e37fbf3bfc8234ead26e2246e1b979e590ac
            46138158a692f9a0c9ac2550758b4d0d4c9fb8af5e595a16d3760c6516443f82
        "),
    );
}

#[test]
fn streebog256_rand() {
    let mut h = Streebog256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("eb5783a2d3f1aa52136701c07c90272a45f017733d898cdfc02302ad2ac8ebed")[..],
    );
}

#[test]
#[rustfmt::skip]
fn streebog512_rand() {
    let mut h = Streebog512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            d78479790925e257b1d65bec84cbe9bbd9bf0abcefb9f99aa065cc533187224f
            2bead756c96297dcd17728a838e3117a9123559be655175bf4cdac0ee11fba75
        ")[..],
    );
}
