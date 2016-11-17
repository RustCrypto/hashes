use gost94::{Gost94, SBox, BLOCK_SIZE};
use generic_array::typenum::U32;
use digest::Digest;
use generic_array::GenericArray;

const S_TEST: SBox = [
    [4,10,9,2,13,8,0,14,6,11,1,12,7,15,5,3],
    [14,11,4,12,6,13,15,10,2,3,8,1,0,7,5,9],
    [5,8,1,13,10,3,4,2,14,15,12,7,6,0,9,11],
    [7,13,10,1,0,8,9,15,14,4,6,12,11,2,5,3],
    [6,12,7,1,5,15,13,8,4,10,9,14,0,3,11,2],
    [4,11,10,0,7,2,1,13,3,6,8,5,9,12,15,14],
    [13,11,4,1,3,15,5,9,0,10,14,7,6,8,2,12],
    [1,15,13,0,5,7,10,4,9,2,3,14,6,11,8,12],
];

#[derive(Clone, Copy)]
pub struct Gost94Test {
    sh: Gost94
}

impl Gost94Test {
    pub fn new() -> Self {
        Self{sh: Gost94::new(S_TEST, [0; BLOCK_SIZE])}
    }
}

impl Default for Gost94Test {
    fn default() -> Self {
        Self::new()    
    }
}

impl Digest for Gost94Test {
    type OutputSize = U32;
    type BlockSize = U32;

    fn input(&mut self, input: &[u8]) {
        self.sh.input(input);
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.sh.result()
    }
}