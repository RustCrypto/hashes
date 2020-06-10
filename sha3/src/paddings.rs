use block_buffer::block_padding::{PadError, Padding, UnpadError};

macro_rules! impl_padding {
    ($name:ident, $pad:expr) => {
        // it does not work with empty enum as it required to have Default impl
        // for it for some unclear reason.
        #[derive(Copy, Clone, Default)]
        pub struct $name;

        impl Padding for $name {
            #[inline(always)]
            fn pad_block(block: &mut [u8], pos: usize) -> Result<(), PadError> {
                if pos >= block.len() {
                    Err(PadError)?
                }
                block[pos] = $pad;
                block[pos + 1..].iter_mut().for_each(|b| *b = 0);
                let n = block.len();
                block[n - 1] |= 0x80;
                Ok(())
            }

            #[inline(always)]
            fn unpad(_data: &[u8]) -> Result<&[u8], UnpadError> {
                unimplemented!();
            }
        }
    };
}

impl_padding!(Keccak, 0x01);
impl_padding!(Sha3, 0x06);
impl_padding!(Shake, 0x1f);
