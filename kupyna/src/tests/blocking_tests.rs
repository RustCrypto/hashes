use crate::{divide_into_blocks, pad_message};
use hex_literal::hex;

const STATE_SIZE_512: usize = 1024;

#[test]
fn block_test_0() {
    let message: [u8; 0] = [];

    let expected_block_count = 1;

    let padded_message = pad_message(&message, 0, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_8() {
    let message: [u8; 1] = [0xFF];

    let expected_block_count = 1;

    let padded_message = pad_message(&message, 8, STATE_SIZE_512);
    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_512() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3F
    "
    );

    let expected_block_count = 1;

    let padded_message = pad_message(&message, 512, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_510() {
    let message = hex!(
        "
        00010203 04050607 08090A0B 0C0D0E0F
        10111213 14151617 18191A1B 1C1D1E1F
        20212223 24252627 28292A2B 2C2D2E2F
        30313233 34353637 38393A3B 3C3D3E3C
    "
    );

    let expected_block_count = 1;

    let padded_message = pad_message(&message, 510, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_1024() {
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

    let expected_block_count = 2;

    let padded_message = pad_message(&message, 1024, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_2048() {
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

    let expected_block_count = 3;

    let padded_message = pad_message(&message, 2048, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_1536() {
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

    let expected_block_count = 2;

    let padded_message = pad_message(&message, 1536, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}

#[test]
fn block_test_655() {
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

    let expected_block_count = 1;

    let padded_message = pad_message(&message, 655, STATE_SIZE_512);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE_512);

    assert_eq!(blocks.len(), expected_block_count);

    // check that all the blocks have equal length
    let block_len = STATE_SIZE_512 / 8;
    for block in blocks {
        assert_eq!(block.len(), block_len);
    }
}
