use hex_literal::hex;
use kupyna::{Digest, Kupyna384};

#[test]
fn kup512_n760() {
    let input = hex!(
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
        "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
        "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E"
    );

    let mut hasher = Kupyna384::default();
    hasher.update(&input);

    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!(
            "D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C7"
            "5016C3DECC2A6E47C50B2F3811E351B8"
        )[..],
    );
}
