use digest::FixedOutput;
use digest::KeyInit;
use digest::Update;
use hex_literal::hex;

use multimixer_128::Multimixer;

// digest::new_test!(toy_main, "toy", Toy, fixed_reset_test); Need to find out how to make .blb testdata.

#[test]
fn multimixer_test() {
    let key = [0x42u8; 32];
    let data = [0x69u8; 32];
    let mut h = Multimixer::new(&key.into());
    h.update(&data);
    assert_eq!(
        h.finalize_fixed().as_slice(),
        &hex!("c42ec87c23422526bf90f16eb222ee6e")[..]
    );
}
