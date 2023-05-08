//! Experimental pure Rust implementation of the KangarooTwelve
//! cryptographic hash algorithm, based on the reference implementation:
//!
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-kangarootwelve/>

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest;

use core::fmt;
use digest::block_buffer::Eager;
use digest::consts::{U128, U168};
use digest::core_api::{
    AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, ExtendableOutputCore,
    UpdateCore, XofReaderCore, XofReaderCoreWrapper,
};
use digest::{ExtendableOutputReset, HashMarker, Reset, Update, XofReader};

use sha3::{TurboShake128, TurboShake128Core, TurboShake128ReaderCore};

/// Implement tree hash functions such as KangarooTwelve or MarsupilamiFourteen.
#[macro_export]
macro_rules! impl_tree_hash {
    (
        $name:ident, $full_name:ident, $reader:ident, $reader_full:ident,
        $tshk:ident, $tshk_full:ident, $tshk_reader_full:ident, $rate:ident, $round_count: ident, $chaining_value_size: ident, $alg_name:expr $(,)?
    ) => {
        const CHUNK_SIZE: usize = 8192;
        const LENGTH_ENCODE_SIZE: usize = 255;

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " hasher state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $name<'cs> {
            customization: &'cs [u8],
            buffer: [u8; CHUNK_SIZE],
            bufpos: usize,
            final_tshk: $tshk_full,
            chain_tshk: $tshk_full,
            chain_length: usize,
        }

        impl<'cs> $name<'cs> {
            /// Creates a new KangarooTwelve instance with the given customization.
            pub fn new(customization: &'cs [u8]) -> Self {
                Self {
                    customization,
                    buffer: [0u8; CHUNK_SIZE],
                    bufpos: 0usize,
                    final_tshk: $tshk_full::from_core(<$tshk>::new_with_round_count(
                        0x06,
                        $round_count,
                    )),
                    chain_tshk: $tshk_full::from_core(<$tshk>::new_with_round_count(
                        0x0B,
                        $round_count,
                    )),
                    chain_length: 0usize,
                }
            }
        }

        impl HashMarker for $name<'_> {}

        impl BlockSizeUser for $name<'_> {
            type BlockSize = U128;
        }

        impl BufferKindUser for $name<'_> {
            type BufferKind = Eager;
        }

        impl UpdateCore for $name<'_> {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                for block in blocks {
                    self.buffer[self.bufpos..self.bufpos + 128].clone_from_slice(block);
                    self.bufpos += 128;

                    if self.bufpos != CHUNK_SIZE {
                        continue;
                    }

                    if self.chain_length == 0 {
                        self.final_tshk.update(&self.buffer);
                        self.final_tshk
                            .update(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
                    } else {
                        let mut result = [0u8; $chaining_value_size];
                        self.chain_tshk.update(&self.buffer);
                        self.chain_tshk.finalize_xof_reset_into(&mut result);
                        self.final_tshk.update(&result);
                    }

                    self.chain_length += 1;
                    self.buffer = [0u8; CHUNK_SIZE];
                    self.bufpos = 0;
                }
            }
        }

        impl ExtendableOutputCore for $name<'_> {
            type ReaderCore = $reader;

            #[inline]
            fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
                let mut lenbuf = [0u8; LENGTH_ENCODE_SIZE];

                // Digest customization
                buffer.digest_blocks(self.customization, |block| self.update_blocks(block));
                buffer.digest_blocks(
                    length_encode(self.customization.len(), &mut lenbuf),
                    |block| self.update_blocks(block),
                );

                // Read leftover data from buffer
                self.buffer[self.bufpos..(self.bufpos + buffer.get_pos())]
                    .copy_from_slice(buffer.get_data());
                self.bufpos += buffer.get_pos();

                // Calculate final node
                let tshk = if self.chain_length == 0 {
                    // Input didnot exceed a single chaining value
                    $tshk_full::from_core(<$tshk>::new_with_round_count(0x07, $round_count))
                        .chain(&self.buffer[..self.bufpos])
                        .finalize_xof_reset()
                } else {
                    // Calculate last chaining value
                    let mut result = [0u8; $chaining_value_size];
                    self.chain_tshk.update(&self.buffer[..self.bufpos]);
                    self.chain_tshk.finalize_xof_reset_into(&mut result);
                    self.final_tshk.update(&result);
                    // Pad final node calculation
                    self.final_tshk
                        .update(length_encode(self.chain_length, &mut lenbuf));
                    self.final_tshk.update(&[0xff, 0xff]);
                    self.final_tshk.finalize_xof_reset()
                };
                $reader { tshk }
            }
        }

        impl Default for $name<'_> {
            #[inline]
            fn default() -> Self {
                Self {
                    customization: &[],
                    buffer: [0u8; CHUNK_SIZE],
                    bufpos: 0usize,
                    final_tshk: $tshk_full::from_core(<$tshk>::new_with_round_count(
                        0x06,
                        $round_count,
                    )),
                    chain_tshk: $tshk_full::from_core(<$tshk>::new_with_round_count(
                        0x0B,
                        $round_count,
                    )),
                    chain_length: 0usize,
                }
            }
        }

        impl Reset for $name<'_> {
            #[inline]
            fn reset(&mut self) {
                *self = Self::new(self.customization);
            }
        }

        impl AlgorithmName for $name<'_> {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_name))
            }
        }

        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        #[doc = "Core "]
        #[doc = $alg_name]
        #[doc = " reader state."]
        #[derive(Clone)]
        #[allow(non_camel_case_types)]
        pub struct $reader {
            tshk: XofReaderCoreWrapper<$tshk_reader_full>,
        }

        impl BlockSizeUser for $reader {
            type BlockSize = $rate; // TurboSHAKE128 block size
        }

        impl XofReaderCore for $reader {
            #[inline]
            fn read_block(&mut self) -> Block<Self> {
                let mut block = Block::<Self>::default();
                self.tshk.read(&mut block);
                block
            }
        }

        #[doc = $alg_name]
        #[doc = " hasher state."]
        pub type $full_name<'cs> = CoreWrapper<$name<'cs>>;

        #[doc = $alg_name]
        #[doc = " reader state."]
        pub type $reader_full = XofReaderCoreWrapper<$reader>;

        fn length_encode(mut length: usize, buffer: &mut [u8; LENGTH_ENCODE_SIZE]) -> &mut [u8] {
            let mut bufpos = 0usize;
            while length > 0 {
                buffer[bufpos] = (length % 256) as u8;
                length /= 256;
                bufpos += 1;
            }
            buffer[..bufpos].reverse();

            buffer[bufpos] = bufpos as u8;
            bufpos += 1;

            &mut buffer[..bufpos]
        }
    };
}

const K12_ROUND_COUNT: usize = 12;
const K12_CHAINING_VALUE_SIZE: usize = 32;

impl_tree_hash!(
    KangarooTwelveCore,
    KangarooTwelve,
    KangarooTwelveReaderCore,
    KangarooTwelveReader,
    TurboShake128Core,
    TurboShake128,
    TurboShake128ReaderCore,
    U168,
    K12_ROUND_COUNT,
    K12_CHAINING_VALUE_SIZE,
    "KangarooTwelve",
);

#[test]
fn test_length_encode() {
    let mut buffer = [0u8; LENGTH_ENCODE_SIZE];
    assert_eq!(length_encode(0, &mut buffer), &[0x00]);
    assert_eq!(length_encode(12, &mut buffer), &[0x0C, 0x01]);
    assert_eq!(length_encode(65538, &mut buffer), &[0x01, 0x00, 0x02, 0x03]);
}
