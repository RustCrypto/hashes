// #![no_std]

use digest::dev::{digest_test, xof_test};
use digest::{new_test, ExtendableOutput, XofReader};
use sha3::digest::{Reset, Update};
use sha3::{CShake128, CShake256};
use std::fmt::Debug;

new_test!(keccak_224, "keccak_224", sha3::Keccak224, digest_test);
new_test!(keccak_256, "keccak_256", sha3::Keccak256, digest_test);
new_test!(keccak_384, "keccak_384", sha3::Keccak384, digest_test);
new_test!(keccak_512, "keccak_512", sha3::Keccak512, digest_test);
// tests are from https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171
new_test!(
    keccak_256_full,
    "keccak_256_full",
    sha3::Keccak256Full,
    digest_test
);

new_test!(sha3_224, "sha3_224", sha3::Sha3_224, digest_test);
new_test!(sha3_256, "sha3_256", sha3::Sha3_256, digest_test);
new_test!(sha3_384, "sha3_384", sha3::Sha3_384, digest_test);
new_test!(sha3_512, "sha3_512", sha3::Sha3_512, digest_test);

new_test!(shake128, "shake128", sha3::Shake128, xof_test);
new_test!(shake256, "shake256", sha3::Shake256, xof_test);

fn cshake_test_helper<F>(data: &[u8], test: F)
where
    F: Fn(&[u8], &[u8], &[u8]) -> Option<&'static str>,
{
    use digest::dev::blobby::Blob3Iterator;

    for (i, row) in Blob3Iterator::new(data).unwrap().enumerate() {
        let customization = row[0];
        let input = row[1];
        let output = row[2];
        if let Some(desc) = test(customization, input, output) {
            panic!(
                "\n\
                         Failed test №{}: {}\n\
                         input:\t{:?}\n\
                         output:\t{:?}\n",
                i, desc, input, output,
            );
        }
    }
}

#[test]
fn test_cshake256() {
    cshake_test_helper(
        include_bytes!("data/cshake256.blb"),
        |customization, input, output| {
            xof_test_with_new(input, output, || CShake256::new(customization))
        },
    )
}

#[test]
fn test_cshake128() {
    cshake_test_helper(
        include_bytes!("data/cshake128.blb"),
        |customization, input, output| {
            xof_test_with_new(input, output, || CShake128::new(customization))
        },
    )
}

pub fn xof_test_with_new<D, F>(input: &[u8], output: &[u8], new: F) -> Option<&'static str>
where
    D: Update + ExtendableOutput + Debug + Reset + Clone,
    F: Fn() -> D,
{
    let mut hasher = new();
    let mut buf = [0u8; 1024];
    // Test that it works when accepting the message all at once
    hasher.update(input);

    let mut hasher2 = hasher.clone();
    {
        let out = &mut buf[..output.len()];
        hasher.finalize_xof().read(out);

        if out != output {
            return Some("whole message");
        }
    }

    // Test if hasher resets correctly
    hasher2.reset();
    hasher2.update(input);

    {
        let out = &mut buf[..output.len()];
        hasher2.finalize_xof().read(out);

        if out != output {
            return Some("whole message after reset");
        }
    }

    // Test if hasher accepts message in pieces correctly
    let mut hasher = new();
    let len = input.len();
    let mut left = len;
    while left > 0 {
        let take = (left + 1) / 2;
        hasher.update(&input[len - left..take + len - left]);
        left -= take;
    }

    {
        let out = &mut buf[..output.len()];
        hasher.finalize_xof().read(out);
        if out != output {
            return Some("message in pieces");
        }
    }

    // Test reading from reader byte by byte
    let mut hasher = new();
    hasher.update(input);

    let mut reader = hasher.finalize_xof();
    let out = &mut buf[..output.len()];
    for chunk in out.chunks_mut(1) {
        reader.read(chunk);
    }

    if out != output {
        return Some("message in pieces");
    }
    None
}
