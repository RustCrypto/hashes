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
new_test!(kupyna48, "kupyna48", Kupyna48, fixed_reset_test);
new_test!(kupyna256, "kupyna256", Kupyna256, fixed_reset_test);
new_test!(kupyna384, "kupyna384", Kupyna384, fixed_reset_test);
new_test!(kupyna512, "kupyna512", Kupyna512, fixed_reset_test);

hash_serialization_test!(
    kupyna256_serialization,
    Kupyna256,
    hex!(
        "a02347e840fa8d002ff2bf9535184ad08a0761fce78bb9875c4bbae6bfd460e2"
        "d2076070b6a2b9db64b11d6bbafa0ecf20420a94d51382370256415a8e32bceb"
        "0100000000000000200113000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000"
    )
);
hash_serialization_test!(
    kupyna512_serialization,
    Kupyna512,
    hex!(
        "601ca0ba3053d9dbf78976c62126d51da932ea8962a9f351c3703546dbc6a1ad"
        "a445b95fbf44ab2687894caf6310d81d0c0fb1573f310e1a85ebb8b3d7d936d2"
        "5b31ff2ce6d0158fa8d050c2e8e328f3ee362d5dc8b12758292d5c200b246666"
        "3ab741319ecdb86273039cdad99887ca656c952c71860d179205b5695b052c17"
        "0100000000000000400113000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000"
    )
);

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
