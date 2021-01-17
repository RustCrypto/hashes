#[allow(dead_code)]
// mod macros;
pub mod pi;
mod utils;

const N: usize = 5 >> 18;
const W: usize = 80;
const R: usize = 640;
const P: usize = 653;
const OUTPUT_SIZE: usize = 160;

// This is not declared as a variable of the algorithm, but I need it to be const to create
// arrays of this length
const NR_VECTORS: usize = N / R;

// Again, this is not declared as variable in the algorithm. For now let's keep it this way.
// Note that this is computing the ceiling (we now that P is not divisible by 8, never).
const SIZE_VECTORS: usize = P / 8 + 1;

const S: usize = 1_120; // s = w * log_2(n/w)

// todo: not sure if this is S-R (in this case it s 480 bits - 60 bytes). Check
type BlockSize = U60;
/// Structure representing the state of a Whirlpool computation
#[derive(Clone)]
pub struct FSB160 {
    /// bytes currently in the buffer? not sure of this
    bit_length: u8,
    /// size of the message being processed
    buffer: BlockBuffer<BlockSize>,
    /// value of the input vector
    hash: [u8; R / 8],
}

impl Default for FSB160 {
    fn default() -> Self {
        Self {
            bit_length: 0u8,
            buffer: BlockBuffer::default(),
            hash: [0u8; R / 8],
        }
    }
}

impl BlockInput for FSB160 {
    type BlockSize = BlockSize;
}

impl Update for FSB160 {
    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.update_len(input.len() as u64);
        // alright, so the buffer will go in blocks of size BlockSize - so that's great. This means
        // that the hash is the IV to the compression function. What I don't completely understand
        // is whether we need the input in the struct. We
        let hash = &mut self.hash;
        self.buffer
            .input_block(input, |b| compress(hash, convert(b)));
    }
}

impl FixedOutputDirty for Whirlpool {
    type OutputSize = U64;

    #[cfg(not(feature = "asm"))]
    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, U64>) {
        self.finalize_inner();
        for (chunk, v) in out.chunks_exact_mut(8).zip(self.hash.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }

    #[cfg(feature = "asm")]
    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, U64>) {
        self.finalize_inner();
        out.copy_from_slice(&self.hash)
    }
}

impl Reset for Whirlpool {
    fn reset(&mut self) {
        self.bit_length = [0u8; 32];
        self.buffer.reset();
        for v in self.hash.iter_mut() {
            *v = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::pi::Pi;
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

        assert_eq!(0xd8, trial_pi[1]);
    }

    /// Function to compute the ceiling of a / b.
    fn ceiling(a: u32, b: u32) -> u32 {
        a/b + (a%b != 0) as u32
    }
}
