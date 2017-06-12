use block_buffer::Padding;
use byte_tools::zero;

macro_rules! impl_padding {
    ($name:ident, $pad:expr) => {
        // it does not work with empty enum as it required to have Default impl
        // for it for some unclear reason.
        #[derive(Copy, Clone, Default)]
        pub struct $name;

        impl Padding for $name {
            #[inline]
            fn pad(block: &mut [u8], pos: usize) {
                block[pos] = $pad;
                zero(&mut block[pos+1..]);
                let n = block.len();
                block[n-1] |= 0x80;
            }
        }
    }
}

impl_padding!(Keccak, 0x01);
impl_padding!(Sha3, 0x06);
impl_padding!(Shake, 0x1f);
