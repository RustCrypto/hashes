use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use sha1::{Digest, Sha1};

#[cfg(feature = "collision")]
use sha1::checked;

digest::new_test!(sha1_main, "sha1", Sha1, fixed_reset_test);

#[test]
fn sha1_rand() {
    let mut h = Sha1::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("7e565a25a8b123e9881addbcedcd927b23377a78"),
    );
}

#[cfg(feature = "collision")]
#[test]
fn shambles_1() {
    collision_test(
        &include_bytes!("./data/sha-mbles-1.bin")[..],
        hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"),
        hex!("4f3d9be4a472c4dae83c6314aa6c36a064c1fd14"),
    )
}

#[cfg(feature = "collision")]
#[test]
fn shambles_2() {
    collision_test(
        &include_bytes!("./data/sha-mbles-2.bin")[..],
        hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"),
        hex!("9ed5d77a4f48be1dbf3e9e15650733eb850897f2"),
    )
}

#[cfg(feature = "collision")]
#[test]
fn shattered_1() {
    collision_test(
        &include_bytes!("./data/shattered-1.pdf")[..],
        hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        hex!("16e96b70000dd1e7c85b8368ee197754400e58ec"),
    )
}

#[cfg(feature = "collision")]
#[test]
fn shattered_2() {
    collision_test(
        &include_bytes!("./data/shattered-2.pdf")[..],
        hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        hex!("e1761773e6a35916d99f891b77663e6405313587"),
    )
}

#[cfg(feature = "collision")]
fn collision_test(input: &[u8], hash: [u8; 20], mitigated_hash: [u8; 20]) {
    // No detection.
    let mut ctx = checked::Config {
        detect_collision: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.try_finalize();
    assert!(!d.has_collision());
    assert_eq!(&d.hash()[..], hash,);

    // No mitigation.
    let mut ctx = checked::Config {
        safe_hash: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);

    let d = ctx.try_finalize();
    assert!(d.has_collision());
    assert_eq!(&d.hash()[..], hash);

    // No mitigation, no optimization.
    let mut ctx = checked::Config {
        safe_hash: false,
        ubc_check: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.try_finalize();
    assert!(d.has_collision());
    assert_eq!(&d.hash()[..], hash);

    // With mitigation.
    let mut ctx = checked::Sha1::new();
    ctx.update(input);
    let d = ctx.try_finalize();
    assert!(d.has_collision());
    assert_eq!(&d.hash()[..], mitigated_hash);
}
