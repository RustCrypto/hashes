//! The [Tiger][1] hash function.
//!
//! [1]: https://en.wikipedia.org/wiki/Tiger_(hash_function)

#![no_std]
#[macro_use] extern crate opaque_debug;
#[macro_use] extern crate digest;
extern crate block_buffer;
extern crate byte_tools;

use core::mem;
use core::num::Wrapping;

pub use digest::Digest;
use digest::{Input, BlockInput, FixedOutput, Reset};
use digest::generic_array::GenericArray;
use digest::generic_array::typenum::{U24, U64};

use byte_tools::{read_u64v_le, write_u64v_le};

use block_buffer::BlockBuffer;
use block_buffer::byteorder::BE;

#[macro_use]
mod macros;
mod consts;

use consts::*;

type BlockSize = U64;
type Block = GenericArray<u8, BlockSize>;

#[derive(Clone)]
pub struct Tiger {
    buffer: BlockBuffer<U64>,
    len: u64,
    state: TigerState,
}

#[derive(Clone)]
struct TigerState((u64, u64, u64));

const A: u64 = 0x0123456789ABCDEF;
const B: u64 = 0xFEDCBA9876543210;
const C: u64 = 0xF096A5B4C3B2E187;

impl TigerState {
    fn new() -> Self {
        TigerState((A, B, C))
    }

    fn process_block(&mut self, block: &Block) {
        let (a, b, c) = self.0;
        let (mut a, mut b, mut c) = (Wrapping(a), Wrapping(b), Wrapping(c));

        let mut data: [u64; 8] = unsafe { mem::uninitialized() };
        read_u64v_le(&mut data, block);

        let mut data = unsafe { mem::transmute::<_, [Wrapping<u64>; 8]>(data) };

        compress!(data, a, b, c);

        self.0 = (a.0, b.0, c.0);
    }

    fn get(&self) -> (u64, u64, u64) {
        self.0
    }
}

impl Tiger {
    pub fn new() -> Self {
        Tiger {
            buffer: BlockBuffer::default(),
            len: 0,
            state: TigerState::new(),
        }
    }

    fn process_block(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input,
                          |blk| self_state.process_block(blk));
    }

    fn finalize(&mut self) {
        let self_state = &mut self.state;
        self.buffer.len64_padding::<BE, _>(self.len, |blk| self_state.process_block(blk));
    }
}

impl Default for Tiger  {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockInput for Tiger {
    type BlockSize = U64;
}

impl Input for Tiger {
    fn input<B: AsRef<[u8]>>(&mut self, input: B) {
        let input = input.as_ref();
        self.process_block(input);
        self.len += (input.len() << 3) as u64;
    }
}

type Output = GenericArray<u8, U24>;

impl FixedOutput for Tiger {
    type OutputSize = U24;

    fn fixed_result(mut self) -> Output {
        self.finalize();

        let (a, b, c) = self.state.get();

        let mut output: Output = unsafe { mem::uninitialized() };
        write_u64v_le(output.as_mut_slice(), &[a, b, c]);

        output
    }
}

impl Reset for Tiger {
    fn reset(&mut self) {
        self.state = TigerState((A, B, C));
        self.buffer.reset();
        self.len = 0;
    }
}

impl_opaque_debug!(Tiger);
impl_write!(Tiger);

#[cfg(test)]
mod tests {
    use super::*;

    use core::num::ParseIntError;

    fn hex_to_bytes(hex: &str) -> Result<Output, ParseIntError> {
        let mut bytes = [0; 24];
        for i in 0..hex.len()/2 {
            bytes[i] = u8::from_str_radix(&hex[2*i..2*i+2], 16)?;
        }
        Ok(bytes.into())
    }

    fn tiger_hash(input: &[u8]) -> Output {
        let mut hasher = Tiger::new();
        hasher.input(&input);
        hasher.result()
    }

    #[test]
    fn basic_test() {
        let test_cases: &'static [(&'static [u8], &'static str)] = &[
            (b"",                                                                                 "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"),
            (b"a",                                                                                "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809"),
            (b"abc",                                                                              "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"),
            (b"message digest",                                                                   "d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6"),
            (b"abcdefghijklmnopqrstuvwxyz",                                                       "1714a472eee57d30040412bfcc55032a0b11602ff37beee9"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",                         "0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e"),
            (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",                   "8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc"),
            (b"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd"),
        ];

        for (i, &(input, expected_hex)) in test_cases.iter().enumerate() {
            let expected = hex_to_bytes(expected_hex).unwrap();
            let reached = tiger_hash(input);

            assert_eq!((i, &expected), (i, &reached));
        }
    }
}
