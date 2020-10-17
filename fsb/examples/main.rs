use fsb_rust::pi::Pi;

fn main() {
    let mut b: u8 = 0b00001101;
    let mut c: u8 = 0b00001110;
    let mut rotated: u8 = b >> 1;
    let pending_one: u8 = (b << 7) >> 4;
    assert_eq!(rotated | pending_one, c);

    let mut bin_a: u16 = 0b11001110u16;
    let mut bin_b: u16 = 0b01100111u16;
    assert_eq!(bin_a.rotate_right(1), bin_b);
    assert_eq!(bin_b.rotate_left(1), bin_a);

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