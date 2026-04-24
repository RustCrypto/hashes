use ascon_hash256::{AsconHash256, Digest};
use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;

// Test vectors from:
// https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
digest::new_test!(ascon_hash256_kat, AsconHash256, fixed_reset_test);
digest::hash_serialization_test!(ascon_hash256_serialization, AsconHash256);

#[test]
fn ascon_hash256_rand() {
    let mut h = AsconHash256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("DE088A2CEA62A8A4C314D4AAF6C72BDC5ECD5F57B4CE7100A2EBE7EB15FEEDD1"),
    );
}
