use std::marker::PhantomData;
use std::ops::Div;

use byte_tools::write_u64_le;
use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use generic_array::typenum::{Quot, U8, U64};
use matrix::Matrix;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const C_P: [u8; 128] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const C_Q: [u8; 128] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xef, 0xdf, 0xcf, 0xbf, 0xaf, 0x9f, 0x8f, 0x7f, 0x6f, 0x5f, 0x4f, 0x3f, 0x2f, 0x1f, 0x0f,
];

const B: [[u8; 8]; 8] = [
    [2, 2, 3, 4, 5, 3, 5, 7],
    [7, 2, 2, 3, 4, 5, 3, 5],
    [5, 7, 2, 2, 3, 4, 5, 3],
    [3, 5, 7, 2, 2, 3, 4, 5],
    [5, 3, 5, 7, 2, 2, 3, 4],
    [4, 5, 3, 5, 7, 2, 2, 3],
    [3, 4, 5, 3, 5, 7, 2, 2],
    [2, 3, 4, 5, 3, 5, 7, 2],
];

const SHIFTS_P: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
const SHIFTS_Q: [u8; 8] = [0, 3, 5, 7, 0, 2, 4, 6];
const SHIFTS_P_WIDE: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 11];
const SHIFTS_Q_WIDE: [u8; 8] = [1, 3, 5, 11, 0, 2, 4, 6];

pub struct Grostl<OutputSize, BlockSize: ArrayLength<u8>> {
    state: GenericArray<u8, BlockSize>,
    rounds: u8,
    phantom: PhantomData<OutputSize>,
}

fn xor_generic_array<L: ArrayLength<u8>>(
    a1: &GenericArray<u8, L>,
    a2: &GenericArray<u8, L>,
) -> GenericArray<u8, L> {
    let mut res = GenericArray::default();
    for i in 0..L::to_usize() {
        res[i] = a1[i] ^ a2[i];
    }
    res
}

impl<OutputSize, BlockSize> Grostl<OutputSize, BlockSize>
    where OutputSize: ArrayLength<u8>,
          BlockSize: ArrayLength<u8>,
          BlockSize: Div<U64>,
          Quot<BlockSize, U64>: ArrayLength<GenericArray<u8, U8>>,
{
    fn new() -> Grostl<OutputSize, BlockSize> {
        let block_bits = BlockSize::to_usize();
        let block_bytes = block_bits / 8;
        let mut iv = GenericArray::default();
        write_u64_le(&mut iv[..8], block_bits as u64);
        let rounds = if block_bytes == 64 {
            14
        } else {
            debug_assert!(block_bytes == 32);
            10
        };

        Grostl {
            state: iv,
            rounds: rounds,
            phantom: PhantomData,
        }
    }

    fn wide(&self) -> bool {
        let block_bytes = BlockSize::to_usize() / 8;
        if block_bytes == 32 {
            false
        } else {
            debug_assert!(block_bytes == 64);
            true
        }
    }

    fn get_padding_chunk(input: &[u8]) -> Vec<u8> {
        let l = input.len();
        let bs = BlockSize::to_usize();

        let num_padding_bits = -1 * ((8 * l + 64) % bs) as isize;
        let num_padding_bytes = num_padding_bits as usize / 8;
        debug_assert!(num_padding_bytes < 512);

        let mut padding_chunk = Vec::with_capacity(bs / 8);
        padding_chunk.extend(input[l - (l % bs)..].iter());
        padding_chunk.push(128);
        for _ in 0..num_padding_bytes - 1 {
            padding_chunk.push(0)
        }
        let num_blocks = (l + num_padding_bytes) / bs;
        write_u64_le(&mut padding_chunk[bs - 8..], num_blocks as u64);

        padding_chunk
    }

    fn compress(
        &self,
        input_block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        xor_generic_array(
            &xor_generic_array(
                &self.p(&xor_generic_array(&self.state, input_block)),
                &self.q(input_block)
            ),
            &self.state,
        )
    }

    fn block_to_matrix(
        &self,
        block: &GenericArray<u8, BlockSize>,
    ) -> Matrix<U8, Quot<BlockSize, U64>> {
        let mut matrix = Matrix::<U8, Quot<BlockSize, U64>>::default();

        let rows = matrix.rows();
        for i in 0..matrix.cols() {
            for j in 0..rows {
                matrix[j][i] = block[i * rows + j];
            }
        }

        matrix
    }

    fn matrix_to_block(
        &self,
        matrix: &Matrix<U8, Quot<BlockSize, U64>>,
    ) -> GenericArray<u8, BlockSize> {
        let mut block = GenericArray::default();

        let rows = matrix.rows();
        for i in 0..matrix.cols() {
            for j in 0..rows {
                block[i * rows + j] = matrix[j][i];
            }
        }

        block
    }

    fn p(
        &self,
        block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        let shifts = if self.wide() {
            SHIFTS_P_WIDE
        } else {
            SHIFTS_P
        };
        let mut matrix = self.block_to_matrix(block);
        for round in 0..self.rounds {
            self.add_round_constant(&mut matrix, C_P, round);
            self.sub_bytes(&mut matrix);
            self.shift_bytes(&mut matrix, shifts);
            matrix = self.mix_bytes(&matrix);
        }
        self.matrix_to_block(&matrix)
    }

    fn q(
        &self,
        block: &GenericArray<u8, BlockSize>,
    ) -> GenericArray<u8, BlockSize> {
        let shifts = if self.wide() {
            SHIFTS_Q_WIDE
        } else {
            SHIFTS_Q
        };
        let mut matrix = self.block_to_matrix(block);
        for round in 0..self.rounds {
            self.add_round_constant(&mut matrix, C_Q, round);
            self.sub_bytes(&mut matrix);
            self.shift_bytes(&mut matrix, shifts);
            matrix = self.mix_bytes(&matrix);
        }
        self.matrix_to_block(&matrix)
    }

    fn add_round_constant(
        &self,
        matrix: &mut Matrix<U8, Quot<BlockSize, U64>>,
        c: [u8; 128],
        round: u8,
    ) {
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                matrix[i][j] ^= c[i * 8 + j];
                if c[0] == 0x00 && i == 0 {
                    matrix[i][j] ^= round;
                } else if c[0] == 0xff && i == 8 {
                    matrix[i][j] ^= round;
                }
            }
        }
    }

    fn sub_bytes(
        &self,
        matrix: &mut Matrix<U8, Quot<BlockSize, U64>>,
    ) {
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                matrix[i][j] = SBOX[matrix[i][j] as usize];
            }
        }
    }

    fn shift_bytes(
        &self,
        matrix: &mut Matrix<U8, Quot<BlockSize, U64>>,
        shifts: [u8; 8],
    ) {
        let cols = matrix.cols();
        for i in 0..matrix.rows() {
            let shift = shifts[i] as usize;
            if shift == 0 {
                continue;
            }
            let num = (cols + shift - 1) / shift;
            for mut j in (cols - shift..cols).rev() {
                let mut k = 0;
                let mut val = matrix[i][j];
                while k < num {
                    let pos = j.wrapping_sub(shift) % cols;
                    let tmp = matrix[i][pos];
                    matrix[i][pos] = val;
                    val = tmp;
                    j = j.wrapping_sub(shift) % cols;
                    k += 1;
                }
            }
        }
    }

    fn mix_bytes(
        &self,
        matrix: &Matrix<U8, Quot<BlockSize, U64>>,
    ) -> Matrix<U8, Quot<BlockSize, U64>> {
        matrix.mul_array(&B)
    }

    fn finalize(self) -> GenericArray<u8, OutputSize> {
        let a = xor_generic_array(&self.p(&self.state), &self.state);
        GenericArray::clone_from_slice(
            &a[a.len() - (OutputSize::to_usize() / 8)..],
        )
    }
}

impl<OutputSize, BlockSize> Default for Grostl<OutputSize, BlockSize>
    where OutputSize: ArrayLength<u8>,
          BlockSize: ArrayLength<u8>,
          BlockSize: Div<U64>,
          Quot<BlockSize, U64>: ArrayLength<GenericArray<u8, U8>>,
{
    fn default() -> Self { Self::new() }
}

impl<OutputSize, BlockSize> Digest for Grostl<OutputSize, BlockSize>
    where OutputSize: ArrayLength<u8>,
          BlockSize: ArrayLength<u8>,
          BlockSize: Div<U64>,
          Quot<BlockSize, U64>: ArrayLength<GenericArray<u8, U8>>,
{
    type OutputSize = OutputSize;
    type BlockSize = BlockSize;

    fn input(&mut self, input: &[u8]) {
        for chunk in input.chunks(self.block_bytes()) {
            if chunk.len() < self.block_bytes() {
                let padding_chunk =
                    Grostl::<OutputSize, BlockSize>::get_padding_chunk(input);
                self.state = self.compress(
                    GenericArray::from_slice(&padding_chunk),
                );
            } else {
                self.state = self.compress(GenericArray::from_slice(chunk));
            }
        }
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.finalize()
    }
}

#[cfg(test)]
mod test {
    use super::{Grostl, Matrix, SHIFTS_P};
    use generic_array::typenum::{U256, U512};
    use generic_array::GenericArray;

    #[test]
    fn test_shift_bytes() {
        let g: Grostl<U256, U512> = Grostl::default();
        let mut matrix = Matrix::default();
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                matrix[i][j] = (i * matrix.cols() + j) as u8;
            }
        }
        g.shift_bytes(&mut matrix, SHIFTS_P);
        let expected_matrix = Matrix::from_generic_array(
            GenericArray::map_slice(
                &[
                    [0, 1, 2, 3, 4, 5, 6, 7],
                    [9, 10, 11, 12, 13, 14, 15, 8],
                    [18, 19, 20, 21, 22, 23, 16, 17],
                    [27, 28, 24, 25, 31, 24, 25, 26],
                    [36, 37, 38, 39, 32, 33, 34, 35],
                    [42, 46, 47, 40, 41, 42, 40, 41],
                    [54, 55, 48, 49, 48, 49, 52, 53],
                    [63, 56, 56, 58, 59, 60, 61, 62],
                ],
                |s: &[u8; 8]| GenericArray::clone_from_slice(s),
            ),
        );
        assert_eq!(matrix, expected_matrix);
    }
}
