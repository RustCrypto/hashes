use blake2::{digest::FixedOutput, Blake2bMac512, Blake2sMac256};
use hex_literal::hex;

#[test]
fn blake2s_unkeyed() {
    let ctx = Blake2sMac256::new_with_salt_and_personal(None, b"salt", b"persona").unwrap();
    assert_eq!(
        ctx.finalize_fixed(),
        hex!(
            "d7de83e2b1fedd9755db747235b7ba4b"
            "f9773a16b91c6b241e4b1d926160d9eb"
        ),
    );
}

#[test]
fn blake2b_unkeyed() {
    let ctx = Blake2bMac512::new_with_salt_and_personal(None, b"salt", b"persona").unwrap();
    assert_eq!(
        ctx.finalize_fixed(),
        hex!(
            "fa3cd38902ae0602d8f0066f18c579fa"
            "e8068074fbe91f9f5774f841f5ab51fe"
            "39140ad78d6576f8a0b9f8f4c2642211"
            "11c9911d8ba1dbefcd034acdbedb8cde"
        ),
    );
}
