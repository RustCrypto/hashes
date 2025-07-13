use blake2::{Blake2b128, Blake2b256, Blake2b512, Blake2bVar, Digest};
use digest::{Update, VariableOutput};

#[test]
fn compare_blake2b512_empty_input() {
    // Test with empty input using our implementation
    let mut hasher = Blake2b512::new();
    Update::update(&mut hasher, b"");
    let our_result = hasher.finalize();

    // Test with empty input using reference implementation (custom with 64-byte output)
    let ref_result = b2rs::b2b::hash_custom(b"", &[], 64, 1, 1, 0, 0, 0, 0, 0);

    println!("Our Blake2b512 result:       {:?}", hex::encode(our_result));
    println!(
        "Reference Blake2b result:    {:?}",
        hex::encode(&ref_result)
    );

    assert_eq!(our_result.as_slice(), &ref_result[..]);
}

#[test]
fn compare_blake2b256_empty_input() {
    // Test with empty input using our implementation
    let mut hasher = Blake2b256::new();
    Update::update(&mut hasher, b"");
    let our_result = hasher.finalize();

    // Test with empty input using reference implementation (custom with 32-byte output)
    let ref_result = b2rs::b2b::hash_custom(b"", &[], 32, 1, 1, 0, 0, 0, 0, 0);

    println!("Our Blake2b256 result:       {:?}", hex::encode(our_result));
    println!(
        "Reference Blake2b result:    {:?}",
        hex::encode(&ref_result)
    );

    assert_eq!(our_result.as_slice(), &ref_result[..]);
}

#[test]
fn compare_blake2b128_empty_input() {
    // Test with empty input using our implementation
    let mut hasher = Blake2b128::new();
    Update::update(&mut hasher, b"");
    let our_result = hasher.finalize();

    // Test with empty input using reference implementation (custom with 16-byte output)
    let ref_result = b2rs::b2b::hash_custom(b"", &[], 16, 1, 1, 0, 0, 0, 0, 0);

    println!("Our Blake2b128 result:       {:?}", hex::encode(our_result));
    println!(
        "Reference Blake2b result:    {:?}",
        hex::encode(&ref_result)
    );

    assert_eq!(our_result.as_slice(), &ref_result[..]);
}

#[test]
fn compare_blake2b_variable_sizes_empty_input() {
    // Test a range of output sizes from 1 to 64 bytes
    for output_size in [1, 8, 16, 20, 24, 32, 48, 56, 64] {
        // Our implementation
        let mut hasher = Blake2bVar::new(output_size).unwrap();
        Update::update(&mut hasher, b"");
        let mut our_result = vec![0u8; output_size];
        hasher.finalize_variable(&mut our_result).unwrap();

        // Reference implementation
        let ref_result = b2rs::b2b::hash_custom(b"", &[], output_size as u8, 1, 1, 0, 0, 0, 0, 0);

        println!(
            "Size {}: Our result:      {:?}",
            output_size,
            hex::encode(&our_result)
        );
        println!(
            "Size {}: Reference result: {:?}",
            output_size,
            hex::encode(&ref_result)
        );

        assert_eq!(
            our_result, ref_result,
            "Mismatch for output size {}",
            output_size
        );
    }
}

#[test]
fn compare_blake2b_non_empty_input() {
    let test_input = b"The quick brown fox jumps over the lazy dog";

    // Test with our implementation
    let mut hasher = Blake2b512::new();
    Update::update(&mut hasher, test_input);
    let our_result = hasher.finalize();

    // Test with reference implementation
    let ref_result = b2rs::b2b::hash_custom(test_input, &[], 64, 1, 1, 0, 0, 0, 0, 0);

    println!("Non-empty input test:");
    println!("Our Blake2b512 result:       {:?}", hex::encode(our_result));
    println!(
        "Reference Blake2b result:    {:?}",
        hex::encode(&ref_result)
    );

    assert_eq!(our_result.as_slice(), &ref_result[..]);
}
