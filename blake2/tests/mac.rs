#[cfg(not(feature = "reset"))]
use digest::dev::mac_test as test_fn;
#[cfg(feature = "reset")]
use digest::dev::reset_mac_test as test_fn;

use digest::new_mac_test;

new_mac_test!(blake2b_mac_kat, blake2::Blake2bMac512, test_fn);
new_mac_test!(blake2s_mac_kat, blake2::Blake2sMac256, test_fn);

#[test]
fn blake2b_new_test() {
    use blake2::digest::{KeyInit, Mac, array::Array};

    fn run<T: Mac + KeyInit>(key: &[u8]) {
        const DATA: &[u8] = &[42; 300];
        let res1 = T::new(&Array::try_from(key).unwrap())
            .chain_update(DATA)
            .finalize()
            .into_bytes();
        let res2 = T::new_from_slice(key)
            .unwrap()
            .chain_update(DATA)
            .finalize()
            .into_bytes();
        assert_eq!(res1, res2);
    }

    run::<blake2::Blake2sMac256>(&[0x42; 32]);
    run::<blake2::Blake2bMac512>(&[0x42; 64]);
}

#[test]
fn mac_refuses_empty_keys() {
    assert!(
        blake2::Blake2bMac512::new_with_salt_and_personal(Some(&[]), b"salt", b"persona").is_err()
    );
    assert!(
        blake2::Blake2sMac256::new_with_salt_and_personal(Some(&[]), b"salt", b"persona").is_err()
    );
}
