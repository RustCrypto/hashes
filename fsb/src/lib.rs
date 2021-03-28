pub use digest::Digest;

use digest::{consts::{U60, U20},  generic_array::GenericArray};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};
use block_buffer::{BlockBuffer, block_padding::{AnsiX923, ZeroPadding}};

#[allow(dead_code)]
// mod macros;
pub mod pi;
mod utils;
use utils::compress;

// 480 because that is equal to S - R, and OUTPUT_SIZE respectively.
// todo: all of this needs to be divided by 8 -.=
use digest::consts::{U480, U160};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};


use utils::*;

// This is S-R. We'll have to see how we handle it in a macro.
type BlockSize = U60;
type OutputSize = U20;
/// Structure representing the state of a Whirlpool computation
#[derive(Clone)]
pub struct FSB160 {
    /// bit size of the message till the current moment (the bit size is represented by a 64 bit
    /// number)
    bit_length: u64,
    /// size of the message being processed
    buffer: BlockBuffer<BlockSize>,
    /// value of the input vector
    hash: [u8; crate::SIZE_OUTPUT_COMPRESS],
}

impl FSB160 {
    fn update_len(&mut self, len: u64) {
        self.bit_length += len;
    }
    /// If there is enough place to pad with the size, we use AnsiX923, else, we first pad with
    /// zeros, and then a final blcok with AnsiX923.
    /// todo: seems that we don't need to input the size of the message, so maybe BlockBuffer
    /// keeps the state locally.
    /// todo: Check that the padding actually does what we want. Note in the PDF that there is a
    /// specific order for the bytes of the padding.
    fn finalize_inner(&mut self) {
        // padding
        let hash = &mut self.hash;
        // position of the buffer
        let pos = self.buffer.position();
        if pos <= crate::SIZE_MSG_CHUNKS - 8 - 1 {
            let buf = self
                .buffer
                .pad_with::<AnsiX923>()
                .expect("we never use input_lazy");
            compress(hash, convert(buf));
        }
        else {
            let buf = self
                .buffer
                .pad_with::<ZeroPadding>()
                .expect("we never use input_lazy");
            compress(hash, convert(buf));

            let buf = self
                .buffer
                .pad_with::<AnsiX923>()
                .expect("we never use input_lazy");
            compress(hash, convert(buf));
        }
    }
}

// todo: do we need this unsafe function?
fn convert(block: &GenericArray<u8, U60>) -> &[u8; 60] {
    #[allow(unsafe_code)]
        unsafe {
        &*(block.as_ptr() as *const [u8; 60])
    }
}

fn convert(block: &GenericArray<u8, U480>) -> &[u8; BLOCKS_SIZE] {
    #[allow(unsafe_code)]
        unsafe {
        &*(block.as_ptr() as *const [u8; BLOCKS_SIZE])
    }
}

impl Default for FSB {
    fn default() -> Self {
        Self {
<<<<<<< HEAD
            message_length: 0u64,
            buffer: BlockBuffer::default(),
            hash: [0u8; R],
=======
            bit_length: 0u64,
            buffer: BlockBuffer::default(),
            hash: [0u8; crate::SIZE_OUTPUT_COMPRESS],
>>>>>>> compiled and ran, but test failing
        }
    }
}

impl FSB {
    fn update_len(&mut self, len: u64) {
        self.message_length += len;
    }
}

impl BlockInput for FSB {
    type BlockSize = BlockSize;
}

impl Update for FSB {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.update_len(input.len() as u64);
<<<<<<< HEAD
=======

>>>>>>> compiled and ran, but test failing
        let hash = &mut self.hash;
        self.buffer
            .input_block(input, |b| compress(hash, convert(b)));
    }
}

<<<<<<< HEAD
impl FixedOutputDirty for FSB {
    type OutputSize = U160;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, U160>) {
        self.finalize_inner();
        for (chunk, v) in out.chunks_exact_mut(8).zip(self.hash.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Reset for FSB {
    fn reset(&mut self) {
        self.message_length = 0u64;
=======
// todo: This function is unchecked
impl FixedOutputDirty for FSB160 {
    type OutputSize = OutputSize;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, OutputSize>) {
        self.finalize_inner();
        let final_whirpool = final_compression(self.hash);
        out.copy_from_slice(&final_whirpool)
    }
}

impl Reset for FSB160 {
    fn reset(&mut self) {
>>>>>>> compiled and ran, but test failing
        self.buffer.reset();
        self.hash = [0u8; R];
    }
<<<<<<< HEAD
}
=======
}

digest::impl_write!(Whirlpool);

#[cfg(test)]
mod tests {
    use crate::pi::Pi;
    use crate::{FSB160, Digest};

    #[test]
    fn test_hash_function() {
        // create a hasher object, to use it do not forget to import `Digest` trait
        let mut hasher = FSB160::new();
        // write input message
        hasher.update(b"Hello Whirlpool");
        // read hash digest (it will consume hasher)
        let result = hasher.finalize();

        assert_eq!(1, 1);
    }

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


        // lets try to do the example of the paper of defining the IV with p = 13
        let nr_block = ceiling(13, 8);

        let shift = 8 - (13 % 8);
        let mut trial_pi = Pi[..6].to_vec();

        for i in 0..3 {
            trial_pi[2 * i + 1] <<= shift;
            trial_pi[2 * i + 1] >>= 8 - shift;
        }

//        assert_eq!(0xd8, trial_pi[1]);
    }

    /// Function to compute the ceiling of a / b.
    fn ceiling(a: u32, b: u32) -> u32 {
        a/b + (a%b != 0) as u32
    }
}
>>>>>>> compiled and ran, but test failing
