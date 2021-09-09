use digest::dev::{digest_test, one_million_a};
use digest::new_test;

new_test!(sha224_main, "sha224", sha2::Sha224, digest_test);
new_test!(sha256_main, "sha256", sha2::Sha256, digest_test);
new_test!(sha384_main, "sha384", sha2::Sha384, digest_test);
new_test!(sha512_main, "sha512", sha2::Sha512, digest_test);
new_test!(
    sha512_224_main,
    "sha512_224",
    sha2::Sha512Trunc224,
    digest_test
);
new_test!(
    sha512_256_main,
    "sha512_256",
    sha2::Sha512Trunc256,
    digest_test
);

#[test]
fn sha256_1million_a() {
    let output = include_bytes!("data/sha256_one_million_a.bin");
    one_million_a::<sha2::Sha256>(output);
}

#[test]
#[rustfmt::skip]
fn sha512_avx2_bug() {
    use sha2::Digest;
    use hex_literal::hex;

    let msg = hex!("
        9427a68f37936803ae8209367ae0dfe3dd321f34c411db2649a5483a3aafc5eb
        ba565496b174447dfcf21e49b9fab42ce056da049c17591dd399226af475a6dc
        3178a12fc52b7e262652211b00fbe7749ac5012074fd8ad35714949474155d11
        a7f34d07abd5eaa6ba6937f554cf3cc7728e3af7842739b8040efec89fd9e8d9
        7db6641c959300b19b87175a06c3193890adfd1af5ec5e69306da9d992e134c7
        6ae8d4b07e23c6bb0a354ff83eb97df3718ab8adb64e433683b3586ec8efc2af
        d5b208ff2a65cce1b7c5a305f0a94ed554f3c0d4573d43685e09e26ff4ba3ace
        93d2ff8d6d1161df5cf71048c08d516b6a9bbf4560a76e83bdc19cb7dbf4f5d6
    ");
    let expected = hex!("
        f0b2ed4c82ec51d517e754eba03afc9b1e044695c44da5256608ad6e96e519b4
        380deef1ec6b158426f754e0016d8a09e4a8311fa3b28c74f0ac2a48e963fb21
    ");
    let res = sha2::Sha512::digest(&msg);
    assert_eq!(res[..], expected[..]);
}

#[test]
fn sha512_1million_a() {
    let output = include_bytes!("data/sha512_one_million_a.bin");
    one_million_a::<sha2::Sha512>(output);
}
