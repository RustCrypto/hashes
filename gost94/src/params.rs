pub(crate) type Block = [u8; 32];
pub(crate) type SBox = [[u8; 16]; 8];

/// Trait for storing parameter constants.
// TODO: replace with const generics
pub trait Gost94Params {
    /// S-box value.
    const S_BOX: SBox;
    /// Initialization vector value.
    const H0: Block;
    /// Algorithm name
    const NAME: &'static str;
}

/// CryptoPro parameters.
#[derive(Copy, Clone, Default)]
pub struct CryptoProParam;

impl Gost94Params for CryptoProParam {
    const S_BOX: SBox = [
        [10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15],
        [5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8],
        [7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13],
        [4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3],
        [7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5],
        [7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3],
        [13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11],
        [1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12],
    ];
    const H0: Block = [0; 32];
    const NAME: &'static str = "Gost94CryptoPro";
}

/// S-Box defined in GOST R 34.12-2015.
#[derive(Copy, Clone, Default)]
pub struct S2015Param;

impl Gost94Params for S2015Param {
    const S_BOX: SBox = [
        [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
        [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
        [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
        [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
        [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
        [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
        [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
        [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
    ];
    const H0: Block = [0; 32];
    const NAME: &'static str = "Gost94s2015";
}

/// Test parameters.
#[derive(Copy, Clone, Default)]
pub struct TestParam;

impl Gost94Params for TestParam {
    const S_BOX: SBox = [
        [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
        [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
        [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
        [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
        [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
        [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
        [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
        [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
    ];
    const H0: Block = [0; 32];
    const NAME: &'static str = "Gost94Test";
}
