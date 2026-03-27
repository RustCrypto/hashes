pub(crate) const STATE_LEN: usize = 5;

pub(crate) type State = [u32; STATE_LEN];

pub(crate) const H0: State = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

pub(crate) const K: [u32; 4] = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6];
