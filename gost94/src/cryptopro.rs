use gost94::{Gost94, SBox, BLOCK_SIZE};
use generic_array::typenum::U32;
use digest::Digest;
use generic_array::GenericArray;

const S_CRYPTO_PRO: SBox = [
    [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
    [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
    [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
    [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
    [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
    [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
    [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
    [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
];
#[derive(Clone, Copy)]
pub struct Gost94CryptoPro {
    sh: Gost94
}

impl Gost94CryptoPro {
    pub fn new() -> Self {
        Gost94CryptoPro{sh: Gost94::new(S_CRYPTO_PRO, [0; BLOCK_SIZE])}
    }
}

impl Default for Gost94CryptoPro {
    fn default() -> Self {
        Self::new()    
    }
}

impl Digest for Gost94CryptoPro {
    type OutputSize = U32;
    type BlockSize = U32;

    fn input(&mut self, input: &[u8]) {
        self.sh.input(input);
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.sh.result()
    }
}