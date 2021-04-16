use hex_literal::hex;

use fsb_rust::*;
use digest::Digest;

fn main() {
    // // create a hasher object, to use it do not forget to import `Digest` trait
    // let mut hasher = Fsb160::new();
    // // write input message
    // hasher.update(b"hello");
    // let result = hasher.finalize();
    //
    // assert_eq!(
    //     result[..],
    //     hex!("6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b")[..]
    // );
    //
    // hasher = Fsb160::new();
    // hasher.update(b"tiriri tralala potompompom");
    // let result_1 = hasher.finalize();
    //
    // assert_eq!(
    //     result_1[..],
    //     hex!("bfbd2f301a8ffbcfb60f3964d96d07e6569824f9")[..]
    // );
    //
    // hasher = Fsb160::new();
    // hasher.update(b"hello darkness my old friend, I have come here to see you again.");
    // let result_1 = hasher.finalize();
    //
    // assert_eq!(
    //     result_1[..],
    //     hex!("8fdfdaabe0b804b526018bedda51d009aea12b4d")[..]
    // );

    // create a hasher object, to use it do not forget to import `Digest` trait
    let mut hasher = Fsb224::new();
    // write input message
    hasher.update(b"hello");
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("5b04d5f3c350d00f8815f018d21a2e7289bc6993b4fa167976962537")[..]
    );

    hasher = Fsb224::new();
    hasher.update(b"tiriri tralala potompompom");
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("bd9cc65169789ab20fbba27910a9f5323d0559f107eff3c55656dd23")[..]
    );

    hasher = Fsb224::new();
    hasher.update(b"hello darkness my old friend, I have come here to see you again.");
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("6ed702e1fe264df2bf30f3efd85b95aa256db88d933a4a7d9567f1cc")[..]
    );
}
