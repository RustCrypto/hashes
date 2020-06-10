use core::ops::Div;

use crate::consts::{B, C_P, C_Q, SBOX, SHIFTS_P, SHIFTS_P_WIDE, SHIFTS_Q, SHIFTS_Q_WIDE};
use crate::matrix::Matrix;
use digest::generic_array::typenum::{Quot, U8};
use digest::generic_array::{ArrayLength, GenericArray};

#[derive(Copy, Clone)]
pub struct GroestlState<BlockSize>
where
    BlockSize: ArrayLength<u8> + Div<U8>,
    BlockSize::ArrayType: Copy,
    Quot<BlockSize, U8>: ArrayLength<u8>,
{
    pub state: GenericArray<u8, BlockSize>,
    rounds: u8,
    pub num_blocks: u64,
}

pub fn xor_generic_array<L: ArrayLength<u8>>(
    a1: &GenericArray<u8, L>,
    a2: &GenericArray<u8, L>,
) -> GenericArray<u8, L> {
    let mut res = GenericArray::default();
    for i in 0..L::to_usize() {
        res[i] = a1[i] ^ a2[i];
    }
    res
}

fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        return a;
    }
    gcd(b, a % b)
}

impl<BlockSize> GroestlState<BlockSize>
where
    BlockSize: ArrayLength<u8> + Div<U8>,
    BlockSize::ArrayType: Copy,
    Quot<BlockSize, U8>: ArrayLength<u8>,
{
    pub fn new(output_size: usize) -> Self {
        let block_bytes = BlockSize::to_usize();
        let output_bits = output_size * 8;

        let mut state = GenericArray::default();
        let n = output_bits as u64;
        state[block_bytes - 8..].copy_from_slice(&n.to_be_bytes());
        let rounds = match block_bytes {
            128 => 14,
            64 => 10,
            _ => unreachable!(),
        };

        GroestlState {
            state,
            rounds,
            num_blocks: 0,
        }
    }

    fn wide(&self) -> bool {
        match BlockSize::to_usize() {
            128 => true,
            64 => false,
            _ => unreachable!(),
        }
    }

    pub fn compress(&mut self, input_block: &GenericArray<u8, BlockSize>) {
        self.state = xor_generic_array(
            &xor_generic_array(
                &self.p(&xor_generic_array(&self.state, input_block)),
                &self.q(input_block),
            ),
            &self.state,
        );
        self.num_blocks += 1;
    }

    fn block_to_matrix(
        &self,
        block: &GenericArray<u8, BlockSize>,
    ) -> Matrix<U8, Quot<BlockSize, U8>> {
        let mut matrix = Matrix::<U8, Quot<BlockSize, U8>>::default();

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
        matrix: &Matrix<U8, Quot<BlockSize, U8>>,
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

    pub fn p(&self, block: &GenericArray<u8, BlockSize>) -> GenericArray<u8, BlockSize> {
        let shifts = if self.wide() { SHIFTS_P_WIDE } else { SHIFTS_P };
        let mut matrix = self.block_to_matrix(block);
        for round in 0..self.rounds {
            self.add_round_constant(&mut matrix, C_P, round);
            self.sub_bytes(&mut matrix);
            self.shift_bytes(&mut matrix, shifts);
            matrix = matrix.mul_array(&B);
        }
        self.matrix_to_block(&matrix)
    }

    fn q(&self, block: &GenericArray<u8, BlockSize>) -> GenericArray<u8, BlockSize> {
        let shifts = if self.wide() { SHIFTS_Q_WIDE } else { SHIFTS_Q };
        let mut matrix = self.block_to_matrix(block);
        for round in 0..self.rounds {
            self.add_round_constant(&mut matrix, C_Q, round);
            self.sub_bytes(&mut matrix);
            self.shift_bytes(&mut matrix, shifts);
            matrix = matrix.mul_array(&B);
        }
        self.matrix_to_block(&matrix)
    }

    fn add_round_constant(
        &self,
        matrix: &mut Matrix<U8, Quot<BlockSize, U8>>,
        c: [u8; 128],
        round: u8,
    ) {
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                matrix[i][j] ^= c[i * 16 + j];

                if (c[0] == 0x00 && i == 0) || (c[0] == 0xff && i == 7) {
                    matrix[i][j] ^= round;
                }
            }
        }
    }

    fn sub_bytes(&self, matrix: &mut Matrix<U8, Quot<BlockSize, U8>>) {
        for i in 0..matrix.rows() {
            for j in 0..matrix.cols() {
                matrix[i][j] = SBOX[matrix[i][j] as usize];
            }
        }
    }

    fn shift_bytes(&self, matrix: &mut Matrix<U8, Quot<BlockSize, U8>>, shifts: [u8; 8]) {
        let cols = matrix.cols();
        for i in 0..matrix.rows() {
            let shift = shifts[i] as usize;
            if shift == 0 {
                continue;
            }
            let d = gcd(shift, cols);
            for j in 0..d {
                let mut k = j;
                let tmp = matrix[i][k];
                loop {
                    let pos = k.wrapping_add(shift) % cols;
                    if pos == j {
                        break;
                    }
                    matrix[i][k] = matrix[i][pos];
                    k = pos;
                }
                matrix[i][k] = tmp;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{xor_generic_array, GroestlState};
    use crate::consts::{C_P, C_Q, SHIFTS_P};
    use digest::generic_array::typenum::U64;
    use digest::generic_array::GenericArray;

    fn get_padding_block() -> GenericArray<u8, U64> {
        let padding_block: [u8; 64] = [
            128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 1,
        ];

        GenericArray::clone_from_slice(&padding_block)
    }

    #[test]
    fn test_shift_bytes() {
        let s = GroestlState::<U64>::new(32);
        let mut block = GenericArray::default();
        for i in 0..64 {
            block[i] = i as u8;
        }
        let mut matrix = s.block_to_matrix(&block);
        s.shift_bytes(&mut matrix, SHIFTS_P);
        let block = s.matrix_to_block(&matrix);
        let expected = [
            0, 9, 18, 27, 36, 45, 54, 63, 8, 17, 26, 35, 44, 53, 62, 7, 16, 25, 34, 43, 52, 61, 6,
            15, 24, 33, 42, 51, 60, 5, 14, 23, 32, 41, 50, 59, 4, 13, 22, 31, 40, 49, 58, 3, 12,
            21, 30, 39, 48, 57, 2, 11, 20, 29, 38, 47, 56, 1, 10, 19, 28, 37, 46, 55,
        ];
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn test_p() {
        let padding_chunk = get_padding_block();
        let s = GroestlState::<U64>::new(32);
        let block = xor_generic_array(&s.state, GenericArray::from_slice(&padding_chunk));

        let p_block = s.p(&block);
        let expected = [
            247, 236, 141, 217, 73, 225, 112, 216, 1, 155, 85, 192, 152, 168, 174, 72, 112, 253,
            159, 53, 7, 6, 8, 115, 58, 242, 7, 115, 148, 150, 157, 25, 18, 220, 11, 5, 178, 10,
            110, 94, 44, 56, 110, 67, 107, 234, 102, 163, 243, 212, 49, 25, 46, 17, 170, 84, 5, 76,
            239, 51, 4, 107, 94, 20,
        ];
        assert_eq!(&p_block[..], &expected[..]);
    }

    #[test]
    fn test_q() {
        let padding_chunk = get_padding_block();
        let s = GroestlState::<U64>::new(32);
        let q_block = s.q(GenericArray::from_slice(&padding_chunk));
        let expected = [
            189, 183, 105, 133, 208, 106, 34, 36, 82, 37, 180, 250, 229, 59, 230, 223, 215, 245,
            53, 117, 167, 139, 150, 186, 210, 17, 220, 57, 116, 134, 209, 51, 124, 108, 84, 91, 79,
            103, 148, 27, 135, 183, 144, 226, 59, 242, 87, 81, 109, 211, 84, 185, 192, 172, 88,
            210, 8, 121, 31, 242, 158, 227, 207, 13,
        ];
        assert_eq!(&q_block[..], &expected[..]);
    }

    #[test]
    fn test_block_to_matrix() {
        let s = GroestlState::<U64>::new(32);
        let mut block1 = GenericArray::default();
        for i in 0..block1.len() {
            block1[i] = i as u8;
        }
        let m = s.block_to_matrix(&block1);
        let block2 = s.matrix_to_block(&m);
        assert_eq!(block1, block2);
    }

    #[test]
    fn test_add_round_constant() {
        let padding_chunk = get_padding_block();
        let s = GroestlState::<U64>::new(32);

        let mut m = s.block_to_matrix(GenericArray::from_slice(&padding_chunk));
        s.add_round_constant(&mut m, C_P, 0);
        let b = s.matrix_to_block(&m);
        let expected = [
            128, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0,
            0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 80, 0, 0, 0, 0, 0, 0, 0, 96, 0, 0, 0, 0, 0, 0,
            0, 112, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(&b[..], &expected[..]);

        let mut m = s.block_to_matrix(GenericArray::from_slice(&padding_chunk));
        s.add_round_constant(&mut m, C_Q, 0);
        let b = s.matrix_to_block(&m);
        let expected = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xef, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdf, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xaf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x9f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8e,
        ];
        assert_eq!(&b[..], &expected[..]);
    }
}
