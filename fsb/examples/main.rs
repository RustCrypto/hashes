use fsb_rust::pi::Pi;
use hex_literal::hex;

use whirlpool::{Whirlpool, Digest};
use std::str;
use fsb_rust::*;

fn main() {
    let mut a: u8 = 0b11111111;
    let shifted = a << 7u8;
    // create a hasher object, to use it do not forget to import `Digest` trait
    let mut hasher = FSB160::new();
    // write input message
    hasher.update(b"hello");
    // read hash digest (it will consume hasher)
    let result = hasher.finalize();

    assert_eq!(result[..], hex!("6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b")[..]);


    let mut b: u8 = 0b00001101;
    let mut c: u8 = 0b00001110;
    let mut rotated: u8 = b >> 1;
    assert_eq!(rotated, 0b00000110);
    let pending_one: u8 = (b << 7) >> 4;
    assert_eq!(rotated | pending_one, c);



    let mut bin_a: u16 = 0b11001110u16;
    let mut bin_b: u16 = 0b01100111u16;
    let mut bin_c: u16 = 0b1000000000110011u16;
    assert_eq!(bin_a.rotate_right(1), bin_b);
    assert_eq!(bin_b.rotate_left(1), bin_a);
    assert_eq!(bin_b.rotate_right(1), bin_c);

    let mut vec_a: [u8; 4] = [0b10100010, 0b10100010, 0b10100010, 0b10100010];
    let mut vec_b: [u8; 4] = [0b10100011, 0b11100010, 0b10101010, 0b10100000];
    vec_a.iter_mut()
        .zip(vec_b.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    let expected_vec_c = [0b00000001, 0b01000000, 0b00001000, 0b00000010];
    assert_eq!(vec_a, expected_vec_c);

    let xored: u16 = 0b10101001u16;
    assert_eq!(bin_a^bin_b, xored);

    let cc: u32 = 33u32;
    let aa = cc.rotate_left(3);


    // lets try to do the example of the paper of defining the IV with p = 13
    let nr_block = ceiling(13, 8);

    let shift = 8 - (13 % 8);
    let mut trial_pi = Pi[..6].to_vec();

    for i in 0..3 {
        trial_pi[2 * i + 1] >>= shift;
        trial_pi[2 * i + 1] <<= shift;
    }
    assert_eq!(0xa8, trial_pi[3]);

    assert_eq!(0xc0, 192_u8);
}

/// Function to compute the ceiling of a / b.
fn ceiling(a: u32, b: u32) -> u32 {
    a/b + (a%b != 0) as u32
}

