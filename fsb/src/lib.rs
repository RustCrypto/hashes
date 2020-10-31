#[allow(dead_code)]
// mod macros;
pub mod pi;
mod utils;
use utils::compress;

// 480 because that is equal to S - R, and OUTPUT_SIZE respectively.
// todo: all of this needs to be divided by 8 -.=
use digest::consts::{U480, U160};
use digest::{BlockInput, FixedOutputDirty, Reset, Update};

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
const BLOCKS_SIZE: usize = S - R;

type BlockSize = U480;

/// Structure representing the state of a FSB computation
#[derive(Clone)]
pub struct FSB {
    message_length: u64,
    buffer: BlockBuffer<U480>,
    hash: [u8; R],
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
            message_length: 0u64,
            buffer: BlockBuffer::default(),
            hash: [0u8; R],
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
        let hash = &mut self.hash;
        self.buffer
            .input_block(input, |b| compress(hash, convert(b)));
    }
}

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
        self.buffer.reset();
        self.hash = [0u8; R];
    }
}