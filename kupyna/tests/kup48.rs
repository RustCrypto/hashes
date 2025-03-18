use hex_literal::hex;
use kupyna::{Digest, Kupyna48};

#[test]
fn kup48_n512() {
    let input = hex!(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    );

    let result = Kupyna48::digest(&input);

    assert_eq!(result[..], hex!("2F6631239875")[..]);
}
