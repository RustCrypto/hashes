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
        hex!("454b28a8d158ad63ff59e3f761919c7581ee78d3")[..]
    );
}

#[test]
fn fsb224_rand() {
    let mut h = Fsb224::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("80ef345c462dc88261355eaf44ee2bb7277d01db77b46b2828a918b6")[..]
    );
}

#[test]
fn fsb256_rand() {
    let mut h = Fsb256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize()[..],
        hex!("301cbfd7031de3568bf4c4ffa86c2295bde89937acc8ee470446b8c55b88334a")[..]
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
            d11c0ea4ef363916ad8c2a4d8b4758bf0c36e4de93f2bbaeba037b0726c83179
            0ec4e5d9d3e9d66e0810d391a00bf60e
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
            eb15b6c3626e38141e4f17b3b89d7deed007c4ae727452010601bc4e16deef82
            f81415566defb1aba3db9b1b14746bd81cf3689a0f79e6d00434ff4ca19b3e66
        ")[..]
    );
}
