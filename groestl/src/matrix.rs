use core::ops::{Index, IndexMut};
use digest::generic_array::{ArrayLength, GenericArray};

#[derive(Debug, Eq, PartialEq)]
pub struct Matrix<R: ArrayLength<GenericArray<u8, C>>, C: ArrayLength<u8>> {
    pub state: GenericArray<GenericArray<u8, C>, R>,
}

impl<R, C> Default for Matrix<R, C>
where
    R: ArrayLength<GenericArray<u8, C>>,
    C: ArrayLength<u8>,
{
    fn default() -> Self {
        Matrix {
            state: GenericArray::default(),
        }
    }
}

impl<R, C> Index<usize> for Matrix<R, C>
where
    R: ArrayLength<GenericArray<u8, C>>,
    C: ArrayLength<u8>,
{
    type Output = GenericArray<u8, C>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.state[index]
    }
}

impl<R, C> IndexMut<usize> for Matrix<R, C>
where
    R: ArrayLength<GenericArray<u8, C>>,
    C: ArrayLength<u8>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.state[index]
    }
}

fn poly_mul(a: u8, b: usize) -> usize {
    let mut val = match a {
        2 => b << 1,
        3 => b ^ poly_mul(2, b),
        4 => b << 2,
        5 => b ^ poly_mul(4, b),
        7 => b ^ poly_mul(2, b) ^ poly_mul(4, b),
        _ => unreachable!(),
    };

    if val >= 512 {
        val ^= 0x11b << 1;
    }
    if val >= 256 {
        val ^= 0x11b;
    }
    val
}

impl<R, C> Matrix<R, C>
where
    R: ArrayLength<GenericArray<u8, C>>,
    C: ArrayLength<u8>,
{
    pub fn rows(&self) -> usize {
        R::to_usize()
    }

    pub fn cols(&self) -> usize {
        C::to_usize()
    }

    pub fn mul_array(&self, a: &[[u8; 8]; 8]) -> Self {
        let mut res = Matrix::default();
        for i in 0..8 {
            for j in 0..self.cols() {
                for k in 0..8 {
                    res[i][j] ^= poly_mul(a[i][k], self[k][j] as usize) as u8;
                }
            }
        }

        res
    }
}
