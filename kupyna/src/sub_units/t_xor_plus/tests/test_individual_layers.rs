use crate::sub_units::t_xor_plus::*;
use crate::KupynaH;
use hex_literal::hex;

fn setup_hash_params() -> KupynaH {
    KupynaH::default()
}

#[test]
fn test_add_constant_xor() {
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
        00010203 04050607 18090A0B 0C0D0E0F
        30111213 14151617 28191A1B 1C1D1E1F
        60212223 24252627 78292A2B 2C2D2E2F
        50313233 34353637 48393A3B 3C3D3E3F
        C0414243 44454647 D8494A4B 4C4D4E4F
        F0515253 54555657 E8595A5B 5C5D5E5F
        A0616263 64656667 B8696A6B 6C6D6E6F
        90717273 74757677 88797A7B 7C7D7E7F
    "
    );

    let hash_params = setup_hash_params();

    let input_matrix = block_to_matrix(&input, &hash_params);
    let result = add_constant_xor(input_matrix, 0, &hash_params);
    assert_eq!(result, block_to_matrix(&expected_output, &hash_params));
}

#[test]
fn test_add_constant_plus() {
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
        F3F1F2F3 F4F5F6F7 FBF9FAFB FCFDFEEF
        03020304 050607E8 0B0A0B0C 0D0E0FE0
        13121314 151617D8 1B1A1B1C 1D1E1FD0
        23222324 252627C8 2B2A2B2C 2D2E2FC0
        33323334 353637B8 3B3A3B3C 3D3E3FB0
        43424344 454647A8 4B4A4B4C 4D4E4FA0
        53525354 55565798 5B5A5B5C 5D5E5F90
        63626364 65666788 6B6A6B6C 6D6E6F80
    "
    );

    let hash_params = setup_hash_params();

    let input_matrix = block_to_matrix(&input, &hash_params);
    let result = add_constant_plus(input_matrix, 0, &hash_params);
    assert_eq!(result, block_to_matrix(&expected_output, &hash_params));
}

#[test]
fn test_s_box_layer() {
    let input = hex!(
        "
        00010203 04050607 18090A0B 0C0D0E0F
        30111213 14151617 28191A1B 1C1D1E1F
        60212223 24252627 78292A2B 2C2D2E2F
        50313233 34353637 48393A3B 3C3D3E3F
        C0414243 44454647 D8494A4B 4C4D4E4F
        F0515253 54555657 E8595A5B 5C5D5E5F
        A0616263 64656667 B8696A6B 6C6D6E6F
        90717273 74757677 88797A7B 7C7D7E7F
    "
    );
    let expected_output = hex!(
        "
        A8BB9A4D 6BCB452A 793ADFB3 1790511F
        92152B3D C91CBB83 1F5C71D5 6F5716BD
        34F6C002 B4F4AD11 8E0F7A5E 496DD166
        2E26C445 D15DB794 9C140E1A 5810B2DF
        2F6BD70E 4233C386 C49B4E85 8F95CB99
        81634FEE 963C5530 124918B1 BC37E671
        782B8FFD 6A45B9AA 1C0D2FAB 388CDA60
        EBDC050C 36B56CEC CD62B17C 14A55E5B
    "
    );

    let hash_params = setup_hash_params();

    let input_matrix = block_to_matrix(&input, &hash_params);
    let result = s_box_layer(input_matrix, &hash_params);
    assert_eq!(result, block_to_matrix(&expected_output, &hash_params));
}

#[test]
fn test_rotate_rows() {
    let input = hex!(
        "
        A8BB9A4D 6BCB452A 793ADFB3 1790511F
        92152B3D C91CBB83 1F5C71D5 6F5716BD
        34F6C002 B4F4AD11 8E0F7A5E 496DD166
        2E26C445 D15DB794 9C140E1A 5810B2DF
        2F6BD70E 4233C386 C49B4E85 8F95CB99
        81634FEE 963C5530 124918B1 BC37E671
        782B8FFD 6A45B9AA 1C0D2FAB 388CDA60
        EBDC050C 36B56CEC CD62B17C 14A55E5B
    "
    );
    let expected_output = hex!(
        "
        A86205AB 6A375566 79BBB10C 3845E694
        923A9A7C 368CB9DF 1F15DF4D 14B5DA86
        345C2BB3 6BA56C99 8EF6713D 17CB5E30
        2E0FC0D5 C9904571 9C267A02 6F1C51AA
        2F14C45E B457BB60 C46B0E45 49F416EC
        819BD71A D16DAD5B 12634E0E 585DD12A
        78494F85 4210B71F 1C2B18EE 8F33B283
        EB0D8FB1 9695C3BD CDDC2FFD BC3CCB11
    "
    );

    let hash_params = setup_hash_params();

    let input_matrix = block_to_matrix(&input, &hash_params);
    let result = rotate_rows(input_matrix, &hash_params);
    assert_eq!(result, block_to_matrix(&expected_output, &hash_params));
}

#[test]
fn test_mix_columns() {
    let input = hex!(
        "
        A86205AB 6A375566 79BBB10C 3845E694
        923A9A7C 368CB9DF 1F15DF4D 14B5DA86
        345C2BB3 6BA56C99 8EF6713D 17CB5E30
        2E0FC0D5 C9904571 9C267A02 6F1C51AA
        2F14C45E B457BB60 C46B0E45 49F416EC
        819BD71A D16DAD5B 12634E0E 585DD12A
        78494F85 4210B71F 1C2B18EE 8F33B283
        EB0D8FB1 9695C3BD CDDC2FFD BC3CCB11
    "
    );
    let expected_output = hex!(
        "
        86C37798 D2C341A0 3D40B8B9 E2D021B8
        EDF7EC7C 7624852B E454C7EE 3A2AAD4E
        9D55309E D99527D0 9204D40B 63DC5B6F
        4D2590F2 22831818 1819A801 E26A9090
        2BE1E2D9 F05181F4 596EFABC 35F984EB
        0CCB22FC B22ADC5C 98D3ED83 95CD50D4
        CE5A5216 8ED88C03 081D60B9 B28BAE4D
        FEA83FFB 07F135B5 7178E6C8 9B206AD3
    "
    );

    let hash_params = setup_hash_params();

    let input_matrix = block_to_matrix(&input, &hash_params);
    let result = mix_columns(input_matrix, &hash_params);
    assert_eq!(result, block_to_matrix(&expected_output, &hash_params));
}
