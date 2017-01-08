//! The [MD2][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/MD2_(cryptography)

#![no_std]
extern crate generic_array;
extern crate byte_tools;
extern crate digest;
extern crate digest_buffer;

pub use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::{U16, U48};

// values for the S-table
const S: [u8; 256] =
    [41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192,
     199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103,
     66, 111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187,
     47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128,
     127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
     181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118,
     252, 107, 226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230,
     45, 168, 2, 27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71,
     163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40,
     132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225,
     123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0,
     29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68,
     80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20];

type BlockSize = U16;
type Block = GenericArray<u8, U16>;

#[derive(Copy, Clone)]
struct Md2State {
    x: GenericArray<u8, U48>,
    checksum: GenericArray<u8, U16>,
}

#[derive(Copy, Clone)]
pub struct Md2 {
    buffer: DigestBuffer<BlockSize>,
    state: Md2State,
}


impl Md2State {
    fn new() -> Md2State {
        Md2State {
            x: Default::default(),
            checksum: Default::default(),
        }
    }

    fn process_block(&mut self, input: &Block) {
        // Update state
        for j in 0..16usize {
            self.x[16 + j] = input[j];
            self.x[32 + j] = self.x[16 + j] ^ self.x[j];
        }

        let mut t = 0u8;
        for j in 0..18u8 {
            for k in 0..48usize {
                self.x[k] ^= S[t as usize];
                t = self.x[k];
            }
            t = t.wrapping_add(j);
        }

        // Update checksum
        let mut l = self.checksum[15];
        for j in 0..16usize {
            self.checksum[j] ^= S[(input[j] ^ l) as usize];
            l = self.checksum[j];
        }
    }
}

impl Md2 {
    pub fn new() -> Md2 {
        Md2 {
            buffer: Default::default(),
            state: Md2State::new(),
        }
    }

    fn finalize(&mut self) {
        let self_state = &mut self.state;
        {
            // Padding
            let rem = self.buffer.remaining();
            let mut buffer_end = self.buffer.next(rem);
            for idx in 0..rem {
                buffer_end[idx] = rem as u8;
            }
        }
        self_state.process_block(self.buffer.full_buffer());

        let checksum = self_state.checksum.clone();
        self_state.process_block(&checksum);
    }
}

impl Default for Md2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Digest for Md2 {
    type OutputSize = U16;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &Block| {
            self_state.process_block(d);
        });
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize();

        let mut out = GenericArray::default();
        for (x, y) in self.state.x[0..16].iter().zip(out.iter_mut()) {
            *y = *x;
        }
        out
    }
}
