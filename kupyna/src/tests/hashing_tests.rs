use crate::hash_bw_compat;
use hex_literal::hex;

#[test]
fn hash_test_0() {
    let message: [u8; 0] = [];
    let message_length = 0;

    let expected_hash = hex!(
        "
        656B2F4CD714 62388B64A370
        43EA55DBE445 D452AECD46C3
        298343314EF0 4019BCFA3F04
        265A9857F91B E91FCE197096
        187CEDA78C9C 1C021C294A06
        89198538
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_8() {
    let message: [u8; 1] = [0xFF];
    let message_length = 8;

    let expected_hash = hex!(
        "
        871B18CF754B 72740307A97B
        449ABEB32B64 444CC0D5A4D6
        5830AE545683 7A72D8458F12
        C8F06C98C616 ABE11897F862
        63B5CB77C420 FB375374BEC5
        2B6D0292
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_510() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3C
    "
    );

    let message_length = 510;

    let expected_hash = hex!(
        "
        2F3BBAC9 8E8771D6 E3B8AA30 153ABC4D 
        0C2985E9 1DA1B556 8FD1BDD7 05CCAB7E 
        E8D95D2F C98BFA53 22A241E0 9C896B58 
        284C83F2 488CF943 E4B3DE43 E05F0DEA
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_512() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
    "
    );

    let message_length = 512;

    let expected_hash = hex!(
        "
        3813E210 9118CDFB 5A6D5E72 F7208DCC 
        C80A2DFB 3AFDFB02 F46992B5 EDBE536B 
        3560DD1D 7E29C6F5 3978AF58 B444E37B 
        A685C0DD 910533BA 5D78EFFF C13DE62A
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_655() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
        40414243 44454647 48494A4B 4C4D4E4F
        5050
    "
    );

    let message_length = 655;

    let expected_hash = hex!(
        "
        01B7BDA1 DBA77D73 79F53C2A 498A390D
        E5E688A1 2BC75FEE 9E010CB6 FEBED3B9
        C7023931 C74A7B55 168A1504 7D5E2CB7
        8A8B5CA2 F75E05E8 0CA39803 0E02C7AA
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_1024() {
    let message = hex!(
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

    let message_length = 1024;

    let expected_hash = hex!(
        "
        76ED1AC2 8B1D0143 013FFA87 213B4090
        B3564412 63C13E03 FA060A8C ADA32B97
        9635657F 256B15D5 FCA4A174 DE029F0B
        1B4387C8 78FCC1C0 0E8705D7 83FD7FFE
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_1536() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
        40414243 44454647 48494A4B 4C4D4E4F
        50515253 54555657 58595A5B 5C5D5E5F
        60616263 64656667 68696A6B 6C6D6E6F
        70717273 74757677 78797A7B 7C7D7E7F
        80818283 84858687 88898A8B 8C8D8E8F
        90919293 94959697 98999A9B 9C9D9E9F
        A0A1A2A3 A4A5A6A7 A8A9AAAB ACADAEAF
        B0B1B2B3 B4B5B6B7 B8B9BABB BCBDBEBF
    "
    );

    let message_length = 1536;

    let expected_hash = hex!(
        "
        B189BFE9 87F682F5 F167F0D7 FA565330
        E126B6E5 92B1C55D 44299064 EF95B1A5
        7F3C2D0E CF17869D 1D199EBB D02E8857
        FB8ADD67 A8C31F56 CD82C016 CF743121
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}

#[test]
fn hash_test_2048() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
        40414243 44454647 48494A4B 4C4D4E4F
        50515253 54555657 58595A5B 5C5D5E5F
        60616263 64656667 68696A6B 6C6D6E6F
        70717273 74757677 78797A7B 7C7D7E7F
        80818283 84858687 88898A8B 8C8D8E8F
        90919293 94959697 98999A9B 9C9D9E9F
        A0A1A2A3 A4A5A6A7 A8A9AAAB ACADAEAF
        B0B1B2B3 B4B5B6B7 B8B9BABB BCBDBEBF
        C0C1C2C3 C4C5C6C7 C8C9CACB CCCDCECF
        D0D1D2D3 D4D5D6D7 D8D9DADB DCDDDEDF
        E0E1E2E3 E4E5E6E7 E8E9EAEB ECEDEEEF
        F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF
    "
    );

    let message_length = 2048;

    let expected_hash = hex!(
        "
        0DD03D73 50C409CB 3C29C258 93A0724F
        6B133FA8 B9EB90A6 4D1A8FA9 3B565566
        11EB187D 715A956B 107E3BFC 76482298
        133A9CE8 CBC0BD5E 1436A5B1 97284F7E
    "
    );

    let actual_hash = hash_bw_compat(message.to_vec(), Some(message_length)).unwrap();

    assert_eq!(actual_hash, expected_hash);
}
