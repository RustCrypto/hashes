extern crate digest;
extern crate skein;

use digest::Digest;
use digest::generic_array::typenum::{U32, U64};

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
fn skein_256() {
    for path in &[ "skein_256/test32_0", "skein_256/test32_17", "skein_256/test32_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein256::<U32>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
    for path in &[ "skein_256/test64_0", "skein_256/test64_17", "skein_256/test64_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein256::<U64>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
}

#[test]
fn skein_512() {
    for path in &[ "skein_512/test32_0", "skein_512/test32_17", "skein_512/test32_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein512::<U32>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
    for path in &[ "skein_512/test64_0", "skein_512/test64_17", "skein_512/test64_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein512::<U64>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
}

#[test]
fn skein_1024() {
    for path in &[ "skein_1024/test32_0", "skein_1024/test32_17", "skein_1024/test32_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein1024::<U32>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
    for path in &[ "skein_1024/test64_0", "skein_1024/test64_17", "skein_1024/test64_64" ] {
        let (input, output) = read_files(path);
        let hash = skein::Skein1024::<U64>::digest(&input);
        assert_eq!(&hash[..], &output[..])
    }
}
