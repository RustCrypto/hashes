use hex_literal::hex;

use fsb_rust::*;

fn main() {
    // create a hasher object, to use it do not forget to import `Digest` trait
    let mut hasher = FSB160::new();
    // write input message
    hasher.update(b"hello");
    let result = hasher.finalize();

    assert_eq!(
        result.len(),
        hex!("6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b").len()
    );
    assert_eq!(
        result[..],
        hex!("6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b")[..]
    );

    hasher = FSB160::new();
    hasher.update(b"tiriri tralala potompompom");
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("bfbd2f301a8ffbcfb60f3964d96d07e6569824f9")[..]
    );

    hasher = FSB160::new();
    hasher.update(b"hello darkness my old friend, I have come here to see you again.");
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("8fdfdaabe0b804b526018bedda51d009aea12b4d")[..]
    );
}
