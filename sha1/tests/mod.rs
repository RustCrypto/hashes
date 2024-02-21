use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use sha1::{Digest, Sha1};

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
fn sha1_shambles() {
    let mut h = Sha1::new();

    // TODO: actually load shambles data ;)
    h.update("shambles");
    assert_eq!(
        h.finalize(),
        hex!("0409b8f154f8d5f273085c2c7bc369dc5a188c3b"),
    );
}
