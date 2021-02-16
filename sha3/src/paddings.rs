use digest::block_buffer::block_padding::{generic_array::ArrayLength, Block, Padding, UnpadError};

macro_rules! impl_padding {
    ($name:ident, $pad:expr) => {
        #[derive(Copy, Clone, Default)]
        pub struct $name;

        impl<B: ArrayLength<u8>> Padding<B> for $name {
            #[inline]
            fn pad(block: &mut Block<B>, pos: usize) {
                if pos >= B::USIZE {
                    panic!("`pos` is bigger or equal to block size");
                }
                block[pos] = $pad;
                block[pos + 1..].iter_mut().for_each(|b| *b = 0);
                let n = block.len();
                block[n - 1] |= 0x80;
            }

            fn unpad(_: &Block<B>) -> Result<&[u8], UnpadError> {
                unimplemented!();
            }
        }
    };
}

impl_padding!(Keccak, 0x01);
impl_padding!(Sha3, 0x06);
impl_padding!(Shake, 0x1f);
