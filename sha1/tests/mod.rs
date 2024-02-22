use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use sha1::{Digest, Sha1};

#[cfg(feature = "collision")]
use sha1::CollisionDetectionConfig;

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
    let input = &include_bytes!("./data/sha-mbles-1.bin")[..];

    // No detection.
    let mut ctx = CollisionDetectionConfig {
        detect_collision: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.finalize();
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // No mitigation.
    let mut ctx = CollisionDetectionConfig {
        safe_hash: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);

    // TODO: check for error
    let d = ctx.finalize();
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // No mitigation, no optimization.
    let mut ctx = CollisionDetectionConfig {
        safe_hash: false,
        ubc_check: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.finalize();
    // TODO: check for error
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // With mitigation.
    let mut ctx = Sha1::new();
    ctx.update(input);
    let d = ctx.finalize();
    assert_eq!(&d[..], hex!("4f3d9be4a472c4dae83c6314aa6c36a064c1fd14"));
}

#[test]
fn shambles_2() {
    let input = &include_bytes!("./data/sha-mbles-2.bin")[..];

    // No detection.
    let mut ctx = CollisionDetectionConfig {
        detect_collision: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.finalize();
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // No mitigation.
    let mut ctx = CollisionDetectionConfig {
        safe_hash: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.finalize();
    // TODO: check for error
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // No mitigation, no optimization.
    let mut ctx = CollisionDetectionConfig {
        safe_hash: false,
        ubc_check: false,
        ..Default::default()
    }
    .build();
    ctx.update(input);
    let d = ctx.finalize();
    // TODO: check for error
    assert_eq!(&d[..], hex!("8ac60ba76f1999a1ab70223f225aefdc78d4ddc0"));

    // With mitigation.
    let mut ctx = Sha1::new();
    ctx.update(input);
    let d = ctx.finalize();
    assert_eq!(&d[..], hex!("9ed5d77a4f48be1dbf3e9e15650733eb850897f2"));
}
