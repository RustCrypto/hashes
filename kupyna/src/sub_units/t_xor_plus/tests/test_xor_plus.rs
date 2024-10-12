use crate::sub_units::t_xor_plus::{t_plus_l, t_xor_l};
use crate::KupynaH;
use hex_literal::hex;

fn setup_hash_params() -> KupynaH {
    KupynaH::default()
}

#[test]
fn test_t_xor_l() {
    let input = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
        40414243 44454647 48494A4B 4C4D4E4F
        50515253 54555657 58595A5B 5C5D5E5F
        60616263 64656667 68696A6B 6C6D6E6F
        70717273 74757677 78797A7B 7C7D7E7F
    "
    );

    let expected_output = hex!(
        "
        604B9DCF 7EAA5785 94D183EE F2DD97A3
        2C111C81 70C0A508 6A08C9E4 28811132
        31BEC7B7 1D0EE31D E8363B4A A6AF890B
        DEEE5C96 663A4438 3A400930 60E76515
        2DEBECD2 5B8342C4 EF4E750F C3F4814F
        A9E1D11F E7F6F8CF 3272E7E1 614F91AD
        6F01F728 D8DBBE1F 2AC19777 1E378F8D
        D7D13132 7BF1A943 A955F1F7 C832ADF3
    "
    );

    let hash_params = setup_hash_params();
    let result = t_xor_l(&input, &hash_params);
    assert_eq!(result, expected_output);
}

#[test]
fn test_t_plus_l() {
    let input = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
        40414243 44454647 48494A4B 4C4D4E4F
        50515253 54555657 58595A5B 5C5D5E5F
        60616263 64656667 68696A6B 6C6D6E6F
        70717273 74757677 78797A7B 7C7D7E7F
    "
    );

    let expected_output = hex!(
        "
        36575D99 3036AFDE B2654C1E 13660A9D
        4F0E105C A2336F2B B3690045 259A1A9D
        3F248507 C342A70B 42F74981 ECE46DD0
        5E1D309F 774E1ED2 13247CC8 21461673
        C7419AE1 2B9361F3 2C7538C1 5909B197
        E20F9E09 DD28CDD4 D7C234DB DB479318
        A258A718 0B183317 8A20FCFE 05A6064F
        D7B1EA96 07995E98 D90D2D55 DCF72F5F
    "
    );

    let hash_params = setup_hash_params();
    let result = t_plus_l(&input, &hash_params);
    assert_eq!(result, expected_output);
}
