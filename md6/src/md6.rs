use crate::compress::*;
use crate::consts::*;

use core::fmt;
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, OutputSizeUser, Reset,
        TruncSide, UpdateCore, VariableOutputCore,
    },
    crypto_common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    typenum::{Unsigned, U128, U64},
    HashMarker, Output,
};

const W: usize = MD6_W; // number of bits in a word (64)
const C: usize = MD6_C; // size of compression output in words (16)
const K: usize = MD6_K; // key words per compression block (8)
const B: usize = MD6_B; // data words per compression block (64)

pub struct Md6VarCore {
    d: usize,
    hashbitlen: usize,
    hashval: [u8; C * (W / 8)],
    hexhashval: [char; C * (W / 8) + 1],
    initialized: bool,
    bits_processed: usize,
    compression_calls: usize,
    finalized: bool,
    k: [Md6Word; K],
    keylen: usize,
    l: usize,
    r: usize,
    top: usize,
    b: [[Md6Word; B]; MD6_MAX_STACK_HEIGHT],
    bits: [usize; MD6_MAX_STACK_HEIGHT],
    i_for_level: [u64; MD6_MAX_STACK_HEIGHT],
}

impl HashMarker for Md6VarCore {}

impl BlockSizeUser for Md6VarCore {
    type BlockSize = U128;
}

impl BufferKindUser for Md6VarCore {
    type BufferKind = Eager;
}

impl OutputSizeUser for Md6VarCore {
    type OutputSize = U64;
}

impl UpdateCore for Md6VarCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.update(block, block.len() * 8);
        }
    }
}

impl VariableOutputCore for Md6VarCore {
    const TRUNC_SIDE: TruncSide = TruncSide::Left;

    #[inline]
    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        if output_size > Self::OutputSize::USIZE {
            return Err(digest::InvalidOutputSize);
        }

        Ok(Self::init(output_size * 8))
    }

    #[inline]
    fn finalize_variable_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let databitlen = buffer.get_pos() * 8;
        let block = buffer.pad_with_zeros();
        self.update(&block, databitlen);

        // Create a temporary buffer to store the hash value
        let mut hashval = [0u8; 128];

        // Finalize the hash computation
        self.finalize(&mut hashval);

        // Copy the resulting hash value into the output slice
        for (i, o) in out.iter_mut().enumerate() {
            *o = hashval[i];
        }
    }
}

impl AlgorithmName for Md6VarCore {
    fn write_alg_name(f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Md6")
    }
}

impl Default for Md6VarCore {
    #[inline]
    fn default() -> Self {
        Self::init(256)
    }
}

impl Reset for Md6VarCore {
    #[inline]
    fn reset(&mut self) {
        *self = Self::init(self.d);
    }
}

impl fmt::Debug for Md6VarCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Md6Core { ... }")
    }
}

impl Drop for Md6VarCore {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.hashval.zeroize();
            self.hexhashval.zeroize();
            self.k.zeroize();
            self.b.zeroize();
            self.bits.zeroize();
            self.i_for_level.zeroize();
            self.d.zeroize();
            self.hashbitlen.zeroize();
            self.keylen.zeroize();
            self.l.zeroize();
            self.r.zeroize();
            self.top.zeroize();
            self.compression_calls.zeroize();
            self.bits_processed.zeroize();
            self.initialized.zeroize();
            self.finalized.zeroize();
        }
    }
}

impl SerializableState for Md6VarCore {
    type SerializedStateSize = U64;

    fn serialize(&self) -> SerializedState<Self> {
        let mut serialized_state = SerializedState::<Self>::default();

        // Serialize usize fields
        serialized_state.copy_from_slice(&self.d.to_le_bytes());
        serialized_state.copy_from_slice(&self.hashbitlen.to_le_bytes());
        serialized_state.copy_from_slice(&self.bits_processed.to_le_bytes());
        serialized_state.copy_from_slice(&self.compression_calls.to_le_bytes());
        serialized_state.copy_from_slice(&self.keylen.to_le_bytes());
        serialized_state.copy_from_slice(&self.l.to_le_bytes());
        serialized_state.copy_from_slice(&self.r.to_le_bytes());
        serialized_state.copy_from_slice(&self.top.to_le_bytes());

        // Serialize boolean fields
        serialized_state.copy_from_slice(&(self.initialized as u8).to_le_bytes());
        serialized_state.copy_from_slice(&(self.finalized as u8).to_le_bytes());

        // Serialize arrays
        serialized_state.copy_from_slice(&self.hashval);
        for &c in &self.hexhashval {
            serialized_state.copy_from_slice(&(c as u32).to_le_bytes());
        }
        for &word in &self.k {
            serialized_state.copy_from_slice(&word.to_le_bytes());
        }
        for row in &self.b {
            for &word in row {
                serialized_state.copy_from_slice(&word.to_le_bytes());
            }
        }
        for &bit in &self.bits {
            serialized_state.copy_from_slice(&bit.to_le_bytes());
        }
        for &level in &self.i_for_level {
            serialized_state.copy_from_slice(&level.to_le_bytes());
        }

        serialized_state
    }

    fn deserialize(
        serialized_state: &SerializedState<Self>,
    ) -> Result<Self, DeserializeStateError> {
        let mut offset = 0;

        // Helper function to read a usize from the serialized state
        fn read_usize(serialized_state: &[u8], offset: &mut usize) -> usize {
            let size = core::mem::size_of::<usize>();
            let mut buf = [0u8; core::mem::size_of::<usize>()];
            buf.copy_from_slice(&serialized_state[*offset..*offset + size]);
            *offset += size;
            usize::from_le_bytes(buf)
        }

        // Helper function to read a u64 from the serialized state
        fn read_u64(serialized_state: &[u8], offset: &mut usize) -> u64 {
            let size = 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&serialized_state[*offset..*offset + size]);
            *offset += size;
            u64::from_le_bytes(buf)
        }

        // Helper function to read a boolean from the serialized state
        fn read_bool(serialized: &[u8], offset: &mut usize) -> bool {
            let val = serialized[*offset];
            *offset += 1;
            val != 0
        }

        // Deserialize usize fields
        let d = read_usize(serialized_state, &mut offset);
        let hashbitlen = read_usize(serialized_state, &mut offset);
        let bits_processed = read_usize(serialized_state, &mut offset);
        let compression_calls = read_usize(serialized_state, &mut offset);
        let keylen = read_usize(serialized_state, &mut offset);
        let l = read_usize(serialized_state, &mut offset);
        let r = read_usize(serialized_state, &mut offset);
        let top = read_usize(serialized_state, &mut offset);

        // Deserialize boolean fields
        let initialized = read_bool(serialized_state, &mut offset);
        let finalized = read_bool(serialized_state, &mut offset);

        // Deserialize arrays
        let hashval_len = C * (W / 8);
        let mut hashval = [0u8; C * (W / 8)];
        hashval.copy_from_slice(&serialized_state[offset..offset + hashval_len]);
        offset += hashval_len;

        let mut hexhashval = ['\0'; C * (W / 8) + 1];
        for c in &mut hexhashval {
            let size = 4;
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&serialized_state[offset..offset + size]);
            offset += size;
            *c = char::from_u32(u32::from_le_bytes(buf)).expect("invalid char in serialized state");
        }

        let mut k = [0u64; K];
        for word in &mut k {
            *word = read_u64(serialized_state, &mut offset);
        }

        let mut b = [[0u64; B]; MD6_MAX_STACK_HEIGHT];
        for row in &mut b {
            for word in row.iter_mut() {
                *word = read_u64(serialized_state, &mut offset);
            }
        }

        let mut bits = [0usize; MD6_MAX_STACK_HEIGHT];
        for bit in &mut bits {
            *bit = read_usize(serialized_state, &mut offset);
        }

        let mut i_for_level = [0u64; MD6_MAX_STACK_HEIGHT];
        for level in &mut i_for_level {
            *level = read_u64(serialized_state, &mut offset);
        }

        Ok(Self {
            d,
            hashbitlen,
            hashval,
            hexhashval,
            initialized,
            bits_processed,
            compression_calls,
            finalized,
            k,
            keylen,
            l,
            r,
            top,
            b,
            bits,
            i_for_level,
        })
    }
}

impl Md6VarCore {
    #[inline]
    fn init(d: usize) -> Self {
        //
        Self::full_init(d, None, 0, MD6_DEFAULT_L, default_r(d, 0))
    }

    #[inline]
    fn full_init(d: usize, key: Option<&[u8]>, keylen: usize, l: usize, r: usize) -> Self {
        if key.is_some() {
            assert!(keylen <= K * (W / 8), "bad keylen");
        }
        assert!((1..=512).contains(&d), "bad hashlen");

        let (k, keylen) = match key {
            Some(key) if keylen > 0 => {
                let mut key_bytes = [0x00; 64];
                key_bytes[..keylen.min(64)].copy_from_slice(&key[..keylen.min(64)]);

                let mut k_words = [0; K];

                bytes_to_words(&key_bytes, &mut k_words);

                (k_words, keylen)
            }
            _ => ([0u64; K], 0),
        };

        assert!(l <= 255, "bad L");
        assert!(r <= 255, "bad r");

        let initialized = true;
        let finalized = false;
        let compression_calls = 0;
        let bits_processed = 0;
        let hexhashval = ['\n'; C * (W / 8) + 1];
        let hashval = [0; C * (W / 8)];
        let hashbitlen = 0;
        let top = 1;

        let mut bits = [0; MD6_MAX_STACK_HEIGHT];
        if l == 0 {
            bits[1] = C * W
        };

        let b = [[0; B]; MD6_MAX_STACK_HEIGHT];
        let i_for_level = [0; MD6_MAX_STACK_HEIGHT];

        Md6VarCore {
            d,
            hashbitlen,
            hashval,
            hexhashval,
            initialized,
            bits_processed,
            compression_calls,
            finalized,
            k,
            keylen,
            l,
            r,
            top,
            b,
            bits,
            i_for_level,
        }
    }

    pub fn standard_compress(
        &self,
        c: &mut [Md6Word],
        q: &[Md6Word],
        ell: usize,
        p: usize,
        z: usize,
    ) {
        let mut n = [0; MD6_N];
        let mut a = [0; 5000];

        // check that the input values are sensible
        assert!(!c.is_empty());
        assert!(!q.is_empty());
        assert!(!self.b.is_empty());
        assert!(self.r <= MD6_MAX_R);
        assert!(self.l <= 255);
        assert!(ell <= 255);
        assert!(p <= B * W);
        assert!(self.d <= C * W / 2);
        assert!(!self.k.is_empty());

        let u = make_node_id(ell, self.i_for_level[ell]);
        let v = make_control_word(self.r, self.l, z, p, self.keylen, self.d);

        pack(&mut n, q, self.k, self.b[ell], u, v); // pack input data into N

        compress(c, &mut n, self.r, &mut a); // compress
    }

    #[inline]
    fn compress_block(&mut self, c: &mut [u64], ell: usize, z: usize) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");
        assert!(ell < MD6_MAX_STACK_HEIGHT + 1, "stackoverflow");

        self.compression_calls += 1;

        let p = B * W - self.bits[ell]; // number of padding bits
        let q = get_round_constants(W); // Q constant

        self.standard_compress(c, q, ell, p, z);

        self.bits[ell] = 0; // clear bits used count this level
        self.i_for_level[ell] += 1; // increment i for this level

        self.b[ell] = [0; W]; // clear B for this level
    }

    #[inline]
    fn process(&mut self, ell: usize, is_final: bool) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");

        // not final -- more input will be coming
        if !is_final {
            // if this is a leaf, then we're done
            if self.bits[ell] < B * W {
                return;
            }
        } else if ell == self.top {
            if ell == self.l + 1 {
                // SEQ node
                if self.bits[ell] == C * W && self.i_for_level[ell] > 0 {
                    return;
                }
            } else if ell > 1 && self.bits[ell] == C * W {
                return;
            }
        }

        let mut c = [0x00; C]; // compression output
        let z = if is_final && ell == self.top { 1 } else { 0 }; // is this the last block

        self.compress_block(&mut c, ell, z); // compress block

        // if this is the last block, then we're done
        if z == 1 {
            words_to_bytes(&c, &mut self.hashval);
            return;
        }

        // where should result go To "next level"
        let next_level = (ell + 1).min(self.l + 1);

        if next_level == self.l + 1
            && self.i_for_level[next_level] == 0
            && self.bits[next_level] == 0
        {
            self.bits[next_level] = C * W;
        }

        self.b[next_level][..C].copy_from_slice(&c); // copy c onto the next level
        self.bits[next_level] += C * W;

        if next_level > self.top {
            self.top = next_level;
        }

        self.process(next_level, is_final);
    }

    #[inline]
    fn append_bits(&mut self, src: &[u8], srclen: usize) {
        if srclen == 0 {
            return;
        }

        let mut accum: u16 = 0; // Accumulates bits waiting to be moved, right-justified
        let mut accumlen = 0; // Number of bits in accumulator
        let destlen = self.bits[1];

        // Initialize accum, accumlen, and destination index (di)
        if destlen % 8 != 0 {
            accumlen = destlen % 8;
            accum = self.b[1][destlen / 8] as u16; // Grab partial byte from dest
            accum >>= 8 - accumlen; // Right-justify it in accumulator
        }
        let mut di = destlen / 8; // Index of where next byte will go within dest

        // Ensure dest has enough space
        let new_len = (destlen + srclen + 7) / 8;
        if self.b[1].len() < new_len {
            panic!("destination buffer is too small");
        }

        // Number of bytes (full or partial) in src
        let srcbytes = (srclen + 7) / 8;

        for (i, item) in src.iter().enumerate().take(srcbytes) {
            if i != srcbytes - 1 {
                // Not the last byte
                accum = (accum << 8) ^ src[i] as u16;
                accumlen += 8;
            } else {
                // Last byte
                let newbits = if srclen % 8 == 0 { 8 } else { srclen % 8 };
                accum = (accum << newbits) ^ ((*item as u16) >> (8 - newbits));
                accumlen += newbits;
            }

            // Process as many high-order bits of accum as possible
            while (i != srcbytes - 1 && accumlen >= 8) || (i == srcbytes - 1 && accumlen > 0) {
                let numbits = 8.min(accumlen);
                let mut bits = accum >> (accumlen - numbits); // Right justified
                bits <<= 8 - numbits; // Left justified
                bits &= 0xff00 >> numbits; // Mask
                let bits = bits as u8;
                self.b[1][di] = bits as u64; // Save
                di += 1;
                accumlen -= numbits;
            }
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8], databitlen: usize) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");
        assert!(!data.is_empty(), "null data");

        let mut j = 0;
        while j < databitlen {
            let portion_size = (databitlen - j).min(B * W - self.bits[1]);
            if (portion_size % 8 == 0) && (self.bits[1] % 8 == 0) && (j % 8 == 0) {
                let start = j / 8;
                let end = start + portion_size / 8;
                let data_slice = &data[start..end];
                let mut i = 0;

                while i < data_slice.len() {
                    let byte = data_slice[i];
                    let index_u64 = i / 8;
                    let shift_amount = (7 - i % 8) * 8;

                    self.b[1][(self.bits[1] / 64) + index_u64] |= (byte as u64) << shift_amount;

                    i += 1;
                }
            } else {
                self.append_bits(&data[j / 8..], portion_size);
            }

            j += portion_size;
            self.bits[1] += portion_size;
            self.bits_processed += portion_size;

            if self.bits[1] == B * W && j < databitlen {
                self.process(1, false);
            }
        }
    }

    #[inline]
    fn compute_hex_hashval(&mut self) {
        let hex_digits = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];

        for i in 0..((self.d + 7) / 8) {
            self.hexhashval[2 * i] = hex_digits[((self.hashval[i] >> 4) & 0xf) as usize];
            self.hexhashval[2 * i + 1] = hex_digits[((self.hashval[i]) & 0xf) as usize];
        }

        self.hexhashval[(self.d + 3) / 4] = '\n';
    }

    #[inline]
    fn trim_hashval(&mut self) {
        let full_or_partial_bytes = (self.d + 7) / 8;
        let bits = self.d % 8;

        // move relevant bytes to the front
        for i in 0..full_or_partial_bytes {
            self.hashval[i] = self.hashval[C * (W / 8) - full_or_partial_bytes + i];
        }

        // zero out following byte
        for i in full_or_partial_bytes..(C * (W / 8)) {
            self.hashval[i] = 0;
        }

        // shift result left by (8-bits) bit positions, per byte, if needed
        if bits > 0 {
            for i in 0..full_or_partial_bytes {
                self.hashval[i] <<= 8 - bits;
                if (i + 1) < C * (W / 8) {
                    self.hashval[i] |= self.hashval[i + 1] >> bits;
                }
            }
        }
    }

    #[inline]
    fn finalize(&mut self, hashval: &mut [u8]) {
        // check that input values are sensible
        if !self.initialized {
            panic!("state not init");
        }

        // "finalize" was previously called
        if self.finalized {
            return;
        }

        let mut ell;
        // force any processing that needs doing
        if self.top == 1 {
            ell = 1;
        } else {
            ell = 1;
            while ell <= self.top {
                if self.bits[ell] > 0 {
                    break;
                }
                ell += 1;
            }
        }

        // process starting at level ell, up to root
        self.process(ell, true);

        //
        self.trim_hashval();

        if hashval.iter().all(|&x| x == 0) {
            hashval.copy_from_slice(&self.hashval);
        }

        self.compute_hex_hashval();

        self.finalized = true;
    }
}

const fn get_round_constants(w: usize) -> &'static [Md6Word] {
    if w == 64 {
        &[
            0x7311c2812425cfa0,
            0x6432286434aac8e7,
            0xb60450e9ef68b7c1,
            0xe8fb23908d9f06f1,
            0xdd2e76cba691e5bf,
            0x0cd0d63b2c30bc41,
            0x1f8ccf6823058f8a,
            0x54e5ed5b88e3775d,
            0x4ad12aae0a6d6031,
            0x3e7f16bb88222e0d,
            0x8af8671d3fb50c2c,
            0x995ad1178bd25c31,
            0xc878c1dd04c4b633,
            0x3b72066c7a1552ac,
            0x0d6f3522631effcb,
        ]
    } else if w == 32 {
        &[
            0x7311c281, 0x2425cfa0, 0x64322864, 0x34aac8e7, 0xb60450e9, 0xef68b7c1, 0xe8fb2390,
            0x8d9f06f1, 0xdd2e76cb, 0xa691e5bf, 0x0cd0d63b, 0x2c30bc41, 0x1f8ccf68, 0x23058f8a,
            0x54e5ed5b, 0x88e3775d, 0x4ad12aae, 0x0a6d6031, 0x3e7f16bb, 0x88222e0d, 0x8af8671d,
            0x3fb50c2c, 0x995ad117, 0x8bd25c31, 0xc878c1dd, 0x04c4b633, 0x3b72066c, 0x7a1552ac,
            0x0d6f3522, 0x631effcb,
        ]
    } else if w == 16 {
        &[
            0x7311, 0xc281, 0x2425, 0xcfa0, 0x6432, 0x2864, 0x34aa, 0xc8e7, 0xb604, 0x50e9, 0xef68,
            0xb7c1, 0xe8fb, 0x2390, 0x8d9f, 0x06f1, 0xdd2e, 0x76cb, 0xa691, 0xe5bf, 0x0cd0, 0xd63b,
            0x2c30, 0xbc41, 0x1f8c, 0xcf68, 0x2305, 0x8f8a, 0x54e5, 0xed5b, 0x88e3, 0x775d, 0x4ad1,
            0x2aae, 0x0a6d, 0x6031, 0x3e7f, 0x16bb, 0x8822, 0x2e0d, 0x8af8, 0x671d, 0x3fb5, 0x0c2c,
            0x995a, 0xd117, 0x8bd2, 0x5c31, 0xc878, 0xc1dd, 0x04c4, 0xb633, 0x3b72, 0x066c, 0x7a15,
            0x52ac, 0x0d6f, 0x3522, 0x631e, 0xffcb,
        ]
    } else if W == 8 {
        &[
            0x73, 0x11, 0xc2, 0x81, 0x24, 0x25, 0xcf, 0xa0, 0x64, 0x32, 0x28, 0x64, 0x34, 0xaa,
            0xc8, 0xe7, 0xb6, 0x04, 0x50, 0xe9, 0xef, 0x68, 0xb7, 0xc1, 0xe8, 0xfb, 0x23, 0x90,
            0x8d, 0x9f, 0x06, 0xf1, 0xdd, 0x2e, 0x76, 0xcb, 0xa6, 0x91, 0xe5, 0xbf, 0x0c, 0xd0,
            0xd6, 0x3b, 0x2c, 0x30, 0xbc, 0x41, 0x1f, 0x8c, 0xcf, 0x68, 0x23, 0x05, 0x8f, 0x8a,
            0x54, 0xe5, 0xed, 0x5b, 0x88, 0xe3, 0x77, 0x5d, 0x4a, 0xd1, 0x2a, 0xae, 0x0a, 0x6d,
            0x60, 0x31, 0x3e, 0x7f, 0x16, 0xbb, 0x88, 0x22, 0x2e, 0x0d, 0x8a, 0xf8, 0x67, 0x1d,
            0x3f, 0xb5, 0x0c, 0x2c, 0x99, 0x5a, 0xd1, 0x17, 0x8b, 0xd2, 0x5c, 0x31, 0xc8, 0x78,
            0xc1, 0xdd, 0x04, 0xc4, 0xb6, 0x33, 0x3b, 0x72, 0x06, 0x6c, 0x7a, 0x15, 0x52, 0xac,
            0x0d, 0x6f, 0x35, 0x22, 0x63, 0x1e, 0xff, 0xcb,
        ]
    } else {
        panic!("bad w")
    }
}

fn default_r(d: usize, keylen: usize) -> usize {
    // Default number of rounds is forty plus floor(d/4)
    let mut r = 40 + (d / 4);

    // unless keylen > 0, in which case it must be >= 80 as well
    if keylen > 0 {
        r = 80.max(r);
    }

    r
}

fn bytes_to_words(bytes: &[u8], output: &mut [u64]) -> usize {
    let mut bytes_len = bytes.len();

    assert!(bytes_len != 0, "input slice should not be null");

    assert!(
        core::mem::size_of_val(output) >= bytes_len,
        "output slice is too small."
    );

    let words_to_write = if bytes_len % size_of::<u64>() != 0 {
        bytes_len / size_of::<u64>() + 1
    } else {
        bytes_len / size_of::<u64>()
    };

    for i in 0..words_to_write {
        let mut word: u64 = 0;
        for j in 0..core::cmp::min(size_of::<u64>(), bytes_len) {
            word |= u64::from(bytes[i * size_of::<u64>() + j]) << (8 * (size_of::<u64>() - 1 - j));
        }
        output[i] = word;

        if i != words_to_write - 1 {
            bytes_len -= size_of::<u64>();
        }
    }

    words_to_write
}

fn words_to_bytes(words: &[u64], output: &mut [u8]) {
    assert!(
        output.len() == words.len() * 8,
        "output slice is too small."
    );

    for (i, &word) in words.iter().enumerate() {
        for shift in (0..8).rev() {
            let byte = (word >> (shift * 8)) as u8;
            output[i * 8 + (7 - shift)] = byte;
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Md6VarCore {}
