mod macros;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
//        assert_eq!(0xb9c0, 0xdcc0);
        let mut b: u8 = 0b00001101;
        let mut c: u8 = 0b00001110;
        let mut rotated: u8 = b >> 1;
        let pending_one: u8 = (b << 7) >> 4;
        assert_eq!(rotated | pending_one, c);

        let mut bin_a: u16 = 0b11001110u16;
        let mut bin_b: u16 = 0b01100111u16;
        let mut bin_c: u16 = 0b10110011u16;
        assert_eq!(bin_a.rotate_right(1), bin_b);
        assert_eq!(bin_b.rotate_left(1), bin_a);

        let xored: u16 = 0b10101001u16;
        assert_eq!(bin_a^bin_b, xored);

        let cc: u32 = 33u32;
        let aa = cc.rotate_left(3);

    }
}
