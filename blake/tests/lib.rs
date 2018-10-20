extern crate blake;
extern crate digest;

use digest::Digest;

fn read_files(path: &str) -> (Vec<u8>, Vec<u8>) {
    use std::io::Read;
    let mut input = std::fs::File::open(format!("tests/data/{}.input.bin", path)).unwrap();
    let mut output = std::fs::File::open(format!("tests/data/{}.output.bin", path)).unwrap();
    let mut buf = Vec::new();
    input.read_to_end(&mut buf).unwrap();
    let input = buf.clone();
    buf.clear();
    output.read_to_end(&mut buf).unwrap();
    let output = buf;
    (input, output)
}

#[test]
fn blake_224() {
    for path in &["blake_224/test1", "blake_224/test2"] {
        let (input, output) = read_files(path);
        let hash = blake::Blake224::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
}

#[test]
fn blake_256() {
    for path in &["blake_256/test1", "blake_256/test2"] {
        let (input, output) = read_files(path);
        let hash = blake::Blake256::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
}

#[test]
fn blake_384() {
    for path in &["blake_384/test1", "blake_384/test2"] {
        let (input, output) = read_files(path);
        let hash = blake::Blake384::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
}

#[test]
fn blake_512() {
    for path in &["blake_512/test1", "blake_512/test2"] {
        let (input, output) = read_files(path);
        let hash = blake::Blake512::digest(&input);
        assert_eq!(&hash[..], &output[..]);
    }
}
