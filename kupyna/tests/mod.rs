use hex_literal::hex;
use kupyna::{
    Digest, Kupyna256, Kupyna384, Kupyna512, KupynaShort,
    digest::{
        consts::U6,
        dev::{feed_rand_16mib, fixed_reset_test},
        hash_serialization_test, new_test,
    },
};

type Kupyna48 = KupynaShort<U6>;

// Test vectors from the original paper:
// https://eprint.iacr.org/2015/885.pdf
new_test!(kupyna48_kat, Kupyna48, fixed_reset_test);
new_test!(kupyna256_kat, Kupyna256, fixed_reset_test);
new_test!(kupyna384_kat, Kupyna384, fixed_reset_test);
new_test!(kupyna512_kat, Kupyna512, fixed_reset_test);

hash_serialization_test!(kupyna256_serialization, Kupyna256);
hash_serialization_test!(kupyna512_serialization, Kupyna512);

#[test]
fn kupyna256_rand() {
    let mut h = Kupyna256::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("250067e8dd6f36ec2d184d2cf6dc243d5b45b470cc771a8541fb0357e134c2d7"),
    );
}

#[test]
fn kupyna512_rand() {
    let mut h = Kupyna512::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!(
            "1b91c76a15adade8611ae202e1a1899f12b45e21d1d342f33b5ba27987f2b826"
            "9b2b1ba19c5e6663af24439965ae519a59535f7aa5356352e5134e875b4e3510"
        ),
    );
}
