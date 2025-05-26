use core::fmt;
use digest::{
    ExtendableOutputReset, HashMarker, Reset, Update, XofReader,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, Eager, ExtendableOutputCore,
        UpdateCore, XofReaderCore,
    },
    consts::{U128, U168},
};
use sha3::{TurboShake128, TurboShake128Reader};

const CHUNK_SIZE: usize = 8192;
const CHAINING_VALUE_SIZE: usize = 32;
const LENGTH_ENCODE_SIZE: usize = 255;

/// Core [`KangarooTwelve`] hasher state.
#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct KangarooTwelveCore<'cs> {
    customization: &'cs [u8],
    buffer: [u8; CHUNK_SIZE],
    bufpos: usize,
    final_tshk: TurboShake128<0x06>,
    chain_tshk: TurboShake128<0x0B>,
    chain_length: usize,
}

impl<'cs> KangarooTwelveCore<'cs> {
    /// Creates a new KangarooTwelve instance with the given customization.
    pub fn new(customization: &'cs [u8]) -> Self {
        Self {
            customization,
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: Default::default(),
            chain_tshk: Default::default(),
            chain_length: 0usize,
        }
    }

    fn process_chunk(&mut self) {
        debug_assert!(self.bufpos == CHUNK_SIZE);
        if self.chain_length == 0 {
            self.final_tshk.update(&self.buffer);
        } else {
            self.process_chaining_chunk();
        }

        self.chain_length += 1;
        self.buffer = [0u8; CHUNK_SIZE];
        self.bufpos = 0;
    }

    fn process_chaining_chunk(&mut self) {
        debug_assert!(self.bufpos != 0);
        if self.chain_length == 1 {
            self.final_tshk
                .update(&[0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        }

        let mut result = [0u8; CHAINING_VALUE_SIZE];
        self.chain_tshk.update(&self.buffer[..self.bufpos]);
        self.chain_tshk.finalize_xof_reset_into(&mut result);
        self.final_tshk.update(&result);
    }
}

impl HashMarker for KangarooTwelveCore<'_> {}

impl BlockSizeUser for KangarooTwelveCore<'_> {
    type BlockSize = U128;
}

impl BufferKindUser for KangarooTwelveCore<'_> {
    type BufferKind = Eager;
}

impl UpdateCore for KangarooTwelveCore<'_> {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            if self.bufpos == CHUNK_SIZE {
                self.process_chunk();
            }

            self.buffer[self.bufpos..self.bufpos + 128].clone_from_slice(block);
            self.bufpos += 128;
        }
    }
}

impl ExtendableOutputCore for KangarooTwelveCore<'_> {
    type ReaderCore = KangarooTwelveReaderCore;

    #[inline]
    fn finalize_xof_core(&mut self, buffer: &mut Buffer<Self>) -> Self::ReaderCore {
        let mut lenbuf = [0u8; LENGTH_ENCODE_SIZE];

        // Digest customization
        buffer.digest_blocks(self.customization, |block| self.update_blocks(block));
        buffer.digest_blocks(
            length_encode(self.customization.len(), &mut lenbuf),
            |block| self.update_blocks(block),
        );

        if self.bufpos == CHUNK_SIZE && buffer.get_pos() != 0 {
            self.process_chunk();
        }

        // Read leftover data from buffer
        self.buffer[self.bufpos..(self.bufpos + buffer.get_pos())]
            .copy_from_slice(buffer.get_data());
        self.bufpos += buffer.get_pos();

        // Calculate final node
        if self.chain_length == 0 {
            // Input did not exceed a single chaining value
            let tshk = TurboShake128::<0x07>::default()
                .chain(&self.buffer[..self.bufpos])
                .finalize_xof_reset();
            return KangarooTwelveReaderCore { tshk };
        }

        // Calculate last chaining value
        self.process_chaining_chunk();

        // Pad final node calculation
        self.final_tshk
            .update(length_encode(self.chain_length, &mut lenbuf));
        self.final_tshk.update(&[0xff, 0xff]);

        KangarooTwelveReaderCore {
            tshk: self.final_tshk.finalize_xof_reset(),
        }
    }
}

impl Default for KangarooTwelveCore<'_> {
    #[inline]
    fn default() -> Self {
        Self {
            customization: &[],
            buffer: [0u8; CHUNK_SIZE],
            bufpos: 0usize,
            final_tshk: Default::default(),
            chain_tshk: Default::default(),
            chain_length: 0usize,
        }
    }
}

impl Reset for KangarooTwelveCore<'_> {
    #[inline]
    fn reset(&mut self) {
        *self = Self::new(self.customization);
    }
}

impl AlgorithmName for KangarooTwelveCore<'_> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(stringify!(KangarooTwelve))
    }
}

impl fmt::Debug for KangarooTwelveCore<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(concat!(stringify!(KangarooTwelveCore), " { ... }"))
    }
}

impl Drop for KangarooTwelveCore<'_> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.buffer.zeroize();
            self.bufpos.zeroize();
            self.chain_length.zeroize();
            // final_tshk and chain_tshk zeroized by their Drop impl
        }
    }
}

#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveCore<'_> {}

/// Core [`KangarooTwelve`] reader state.
#[derive(Clone)]
pub struct KangarooTwelveReaderCore {
    tshk: TurboShake128Reader,
}

impl BlockSizeUser for KangarooTwelveReaderCore {
    type BlockSize = U168; // TurboSHAKE128 block size
}

impl XofReaderCore for KangarooTwelveReaderCore {
    #[inline]
    fn read_block(&mut self) -> Block<Self> {
        let mut block = Block::<Self>::default();
        self.tshk.read(&mut block);
        block
    }
}

// `TurboShake128ReaderCore` and the wrapper are zeroized by their Drop impls
#[cfg(feature = "zeroize")]
impl digest::zeroize::ZeroizeOnDrop for KangarooTwelveReaderCore {}

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

#[test]
fn test_length_encode() {
    let mut buffer = [0u8; LENGTH_ENCODE_SIZE];
    assert_eq!(length_encode(0, &mut buffer), &[0x00]);
    assert_eq!(length_encode(12, &mut buffer), &[0x0C, 0x01]);
    assert_eq!(length_encode(65538, &mut buffer), &[0x01, 0x00, 0x02, 0x03]);
}
