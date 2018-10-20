use digest::Digest;

fn read_files(path: &str) -> (Vec<u8>, Vec<u8>) {
    let input = std::fs::read(format!("tests/data/{}.input.bin", path)).unwrap();
    let output = std::fs::read(format!("tests/data/{}.output.bin", path)).unwrap();
    (input, output)
}

#[test]
fn jh_224_0() {
    for path in &[ "jh_224/test_0", "jh_224/test_17", "jh_224/test_64", "jh_224/test_123" ] {
        let (input, output) = read_files(path);
        let hash = jh_x86_64::Jh224::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
    for path in &[ "jh_256/test_0", "jh_256/test_17", "jh_256/test_64", "jh_256/test_123" ] {
        let (input, output) = read_files(path);
        let hash = jh_x86_64::Jh256::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
    for path in &[ "jh_384/test_0", "jh_384/test_17", "jh_384/test_64", "jh_384/test_123" ] {
        let (input, output) = read_files(path);
        let hash = jh_x86_64::Jh384::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
    for path in &[ "jh_512/test_0", "jh_512/test_17", "jh_512/test_64", "jh_512/test_123" ] {
        let (input, output) = read_files(path);
        let hash = jh_x86_64::Jh512::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
}
