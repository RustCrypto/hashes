use std::ops::{Index, IndexMut};

use generic_array::{ArrayLength, GenericArray};

#[derive(Debug, Eq, PartialEq)]
pub struct Matrix<R: ArrayLength<GenericArray<u8, C>>, C: ArrayLength<u8>> {
    state: GenericArray<GenericArray<u8, C>, R>,
}

impl<R, C> Default for Matrix<R, C>
    where R: ArrayLength<GenericArray<u8, C>>,
          C: ArrayLength<u8>,
{
    fn default() -> Self {
        Matrix { state: GenericArray::default() }
    }
}

impl<R, C> Index<usize> for Matrix<R, C>
    where R: ArrayLength<GenericArray<u8, C>>,
          C: ArrayLength<u8>,
{
    type Output = GenericArray<u8, C>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.state[index]
    }
}

impl<R, C> IndexMut<usize> for Matrix<R, C>
    where R: ArrayLength<GenericArray<u8, C>>,
          C: ArrayLength<u8>,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.state[index]
    }
}

impl<R, C> Matrix<R, C>
    where R: ArrayLength<GenericArray<u8, C>>,
          C: ArrayLength<u8>,
{
    #[cfg(test)]
    pub fn from_generic_array(
        state: GenericArray<GenericArray<u8, C>, R>,
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
                        res[i][col] = res[i][col].wrapping_add(
                            a[i][j].wrapping_mul(self[row][col]),
                        );
                    }
                }
            }
        }

        res
    }
}
