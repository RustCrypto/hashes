use digest::dev::{feed_rand_16mib, fixed_reset_test};
use hex_literal::hex;
use sha1::{Digest, Sha1};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

digest::new_test!(sha1_kat, Sha1, fixed_reset_test);
digest::hash_serialization_test!(sha1_serialization, Sha1);

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn sha1_file_hex(path: impl AsRef<Path>) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(sha1_hex(&bytes))
}

#[test]
fn sha1_rand() {
    let mut h = Sha1::new();
    feed_rand_16mib(&mut h);
    assert_eq!(
        h.finalize(),
        hex!("7e565a25a8b123e9881addbcedcd927b23377a78"),
    );
}

///
/// Test vectors from https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data for SHA-1.
///

/// A file containing the ASCII string "abc" results in a 160 bit message digest of
/// a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d.
#[test]
fn abc_file_has_expected_sha1_digest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tester-sha1-{unique}.txt"));

    fs::write(&path, b"abc").expect("should write test file");
    let digest = sha1_file_hex(&path).expect("should hash test file");

    let _ = fs::remove_file(&path);

    assert_eq!(digest, "a9993e364706816aba3e25717850c26c9cd0d89d");
}

/// A file containing the ASCII string "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
/// results in a 160-bit message digest of 84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1.
#[test]
fn long_test_vector_file_has_expected_sha1_digest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tester-sha1-{unique}.txt"));
    let contents = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    fs::write(&path, contents).expect("should write test file");
    let digest = sha1_file_hex(&path).expect("should hash test file");

    let _ = fs::remove_file(&path);

    assert_eq!(digest, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

/// A file containing the binary-coded form of the ASCII string which consists of 1,000,000 repetitions of the character "a" results
/// in a SHA-1 message digest of 34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f.
#[test]
fn one_million_a_file_has_expected_sha1_digest() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after the unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tester-sha1-{unique}.txt"));
    let contents = vec![b'a'; 1_000_000];

    fs::write(&path, contents).expect("should write test file");
    let digest = sha1_file_hex(&path).expect("should hash test file");

    let _ = fs::remove_file(&path);

    assert_eq!(digest, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}
