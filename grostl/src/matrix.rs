use std::ops::{Index, IndexMut};

use generic_array::{ArrayLength, GenericArray};

#[derive(Debug, Eq, PartialEq)]
pub struct Matrix<R: ArrayLength<u8>, C: ArrayLength<GenericArray<u8, R>>> {
    state: GenericArray<GenericArray<u8, R>, C>,
}

impl<R, C> Default for Matrix<R, C>
    where R: ArrayLength<u8>,
          C: ArrayLength<GenericArray<u8, R>>,
{
    fn default() -> Self {
        Matrix { state: GenericArray::default() }
    }
}

impl<R, C> Index<usize> for Matrix<R, C>
    where R: ArrayLength<u8>,
          C: ArrayLength<GenericArray<u8, R>>,
{
    type Output = GenericArray<u8, R>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.state[index]
    }
}

impl<R, C> IndexMut<usize> for Matrix<R, C>
    where R: ArrayLength<u8>,
          C: ArrayLength<GenericArray<u8, R>>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.state[index]
    }
}

impl<R, C> Matrix<R, C>
    where R: ArrayLength<u8>,
          C: ArrayLength<GenericArray<u8, R>>,
{
    #[cfg(test)]
    pub fn from_generic_array(
        state: GenericArray<GenericArray<u8, R>, C>,
    ) -> Self {
        Matrix { state: state }
    }

    pub fn rows(&self) -> usize {
        R::to_usize()
    }

    pub fn cols(&self) -> usize {
        C::to_usize()
    }

    pub fn mul_array(&self, a: &[[u8; 8]; 8]) -> Self {
        let mut res = Matrix::default();

        for row in 0..self.rows() {
            for col in 0..self.cols() {
                for i in 0..8 {
                    for j in 0..8 {
                        res[i][col] += a[i][j] * self[row][col];
                    }
                }
            }
        }

        res
    }
}
