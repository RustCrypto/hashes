use digest::dev::{feed_rand_16mib, fixed_reset_test};
use digest::new_test;
use groestl::{Digest, Groestl224, Groestl256, Groestl384, Groestl512};
use hex_literal::hex;

new_test!(groestl_224_main, "groestl224", Groestl224, fixed_reset_test);
new_test!(groestl_256_main, "groestl256", Groestl256, fixed_reset_test);
new_test!(groestl_384_main, "groestl384", Groestl384, fixed_reset_test);
new_test!(groestl_512_main, "groestl512", Groestl512, fixed_reset_test);

#[test]
fn groestl224_rand() {
    let mut h = Groestl224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("2000744c2f85a7fb4733e97da8db00069dd6defa9186dac3461dfeb8")[..]
    );
}

#[test]
fn groestl256_rand() {
    let mut h = Groestl256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("aac71c789678f627a6474605322ae98d1647e47f405d00b1461b90ee5f0cfbc4")[..]
    );
}

#[test]
#[rustfmt::skip]
fn groestl384_rand() {
    let mut h = Groestl384::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            dab78eea895a6dde0c53dc02fc79c7986f5d6811618ca6e5922f01e8aca9bfeb
            20ed5eda4130bf0ab474ac0b6f0290f8
        ")[..]
    );
}

#[test]
#[rustfmt::skip]
fn groestl512_rand() {
    let mut h = Groestl512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("
            7e4d8257c217c7ae59331126e0f984f145e9789862de7c099675ac29e46424ef
            e93543974fa7113190d492f607f629a03db35ec5551abcb2785ae145fd3c543f
        ")[..],
    );
}
