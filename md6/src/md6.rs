use crate::md6_compress::*;
use crate::md6_consts::*;

const w: usize = md6_w; // number of bits in a word (64)
const c: usize = md6_c; // size of compression output in words (16)
const k: usize = md6_k; // key words per compression block (8)
const b: usize = md6_b; // data words per compression block (64)

pub struct MD6State {
    d: usize,
    hashbitlen: usize,
    hashval: [u8; c * (w / 8)],
    hexhashval: [char; c * (w / 8) + 1],
    initialized: bool,
    bits_processed: usize,
    compression_calls: usize,
    finalized: bool,
    K: [md6_word; k],
    keylen: usize,
    L: usize,
    r: usize,
    top: usize,
    B: [[md6_word; b]; md6_max_stack_height],
    bits: [usize; md6_max_stack_height],
    i_for_level: [md6_word; md6_max_stack_height],
}

impl MD6State {
    pub fn init(d: usize) -> Self {
        //
        Self::full_init(d, None, 0, md6_default_L, md6_default_r(d, 0))
    }

    pub fn full_init(d: usize, key: Option<Vec<u8>>, keylen: usize, L: usize, r: usize) -> Self {
        if key.is_some() {
            assert!(keylen <= k * (w / 8), "bad keylen");
        }
        assert!(!(d < 1 || d > 512 || d > w * c / 2), "bad hashlen");

        let (K, keylen) = match key {
            Some(key) if keylen > 0 => {
                let mut key_bytes = vec![0x00; 64];
                key_bytes[..keylen.min(64)].copy_from_slice(&key[..keylen.min(64)]);

                let k_words = bytes_to_words(&key_bytes);

                (k_words.try_into().unwrap(), keylen)
            }
            _ => ([0u64; k], 0),
        };

        assert!(L <= 255, "bad L");
        assert!(r <= 255, "bad r");

        let initialized = true;
        let finalized = false;
        let compression_calls = 0;
        let bits_processed = 0;
        let hexhashval = ['\n'; c * (w / 8) + 1];
        let hashval = [0; c * (w / 8)];
        let hashbitlen = 0;
        let top = 1;

        let mut bits = [0; md6_max_stack_height];
        if L == 0 {
            bits[1] = c * w
        };

        let B = [[0; b]; md6_max_stack_height];
        let i_for_level = [0; md6_max_stack_height];

        MD6State {
            d,
            hashbitlen,
            hashval,
            hexhashval,
            initialized,
            bits_processed,
            compression_calls,
            finalized,
            K,
            keylen,
            L,
            r,
            top,
            B,
            bits,
            i_for_level,
        }
    }

    fn compress_block(&mut self, C: &mut Vec<u64>, ell: usize, z: usize) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");
        assert!(ell < md6_max_stack_height + 1, "stackoverflow");

        self.compression_calls += 1;

        let p = b * w - self.bits[ell]; // number of padding bits
        let Q = get_Q(w); // Q constant

        md6_standard_compress(
            C,
            Q,
            self.K,
            ell,
            self.i_for_level[ell],
            self.r,
            self.L,
            z,
            p,
            self.keylen,
            self.d,
            self.B[ell],
        );

        self.bits[ell] = 0; // clear bits used count this level
        self.i_for_level[ell] += 1; // increment i for this level

        self.B[ell] = [0; w]; // clear B for this level
    }

    fn process(&mut self, ell: usize, is_final: bool) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");

        // not final -- more input will be coming
        if !is_final {
            // if this is a leaf, then we're done
            if self.bits[ell] < b * w {
                return;
            }
        } else {
            if ell == self.top {
                if ell == self.L + 1 {
                    /* SEQ node */
                    if self.bits[ell] == c * w && self.i_for_level[ell] > 0 {
                        return;
                    }
                } else {
                    if ell > 1 && self.bits[ell] == c * w {
                        return;
                    }
                }
            }
        }

        let mut C = vec![0x00; c]; // compression output
        let z = if is_final && ell == self.top { 1 } else { 0 }; // is this the last block?

        self.compress_block(&mut C, ell, z); // compress block

        // if this is the last block, then we're done
        if z == 1 {
            self.hashval = words_to_bytes(&C).try_into().unwrap();
            return;
        }

        // where should result go? To "next level"
        let next_level = (ell + 1).min(self.L + 1);

        if next_level == self.L + 1
            && self.i_for_level[next_level] == 0
            && self.bits[next_level] == 0
        {
            self.bits[next_level] = c * w;
        }

        self.B[next_level] = C.try_into().unwrap(); // copy C onto the next level
        self.bits[next_level] += c * w;

        if next_level > self.top {
            self.top = next_level;
        }

        self.process(next_level, is_final);
    }

    pub fn update(&mut self, data: Vec<u8>, databitlen: usize) {
        // check that input values are sensible
        assert!(self.initialized, "state not init");
        assert!(!data.is_empty(), "null data");

        let mut j = 0;
        while j < databitlen {
            let portion_size = (databitlen - j).min(b * w - self.bits[1]);
            if (portion_size % 8 == 0) && (self.bits[1] % 8 == 0) && (j % 8 == 0) {
                let start = j / 8;
                let end = start + portion_size / 8;
                let data_slice = &data[start..end];
                let mut i = 0;

                while i < data_slice.len() {
                    let byte = data_slice[i];
                    let index_u64 = i / 8;
                    let shift_amount = (7 - i % 8) * 8;

                    self.B[1][(self.bits[1] / 64) + index_u64] |= (byte as u64) << shift_amount;

                    i += 1;
                }
            } else {
                append_bits(&mut self.B[1].to_vec(), self.bits[1], &data[j / 8..], portion_size);
            }

            j += portion_size;
            self.bits[1] += portion_size;
            self.bits_processed += portion_size;

            if self.bits[1] == b * w && j < databitlen {
                self.process(1, false);
            }
        }
    }

    fn compute_hex_hashval(&mut self) {
        let hex_digits = vec![
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];

        for i in 0..((self.d + 7) / 8) {
            self.hexhashval[2 * i] = hex_digits[((self.hashval[i] >> 4) & 0xf) as usize];
            self.hexhashval[2 * i + 1] = hex_digits[((self.hashval[i]) & 0xf) as usize];
        }

        self.hexhashval[(self.d + 3) / 4] = '\n';
    }

    fn trim_hashval(&mut self) {
        let full_or_partial_bytes = (self.d + 7) / 8;
        let bits = self.d % 8;

        // move relevant bytes to the front
        for i in 0..full_or_partial_bytes {
            self.hashval[i] = self.hashval[c * (w / 8) - full_or_partial_bytes + i];
        }

        // zero out following byte
        for i in full_or_partial_bytes..(c * (w / 8)) {
            self.hashval[i] = 0;
        }

        // shift result left by (8-bits) bit positions, per byte, if needed
        if bits > 0 {
            for i in 0..full_or_partial_bytes {
                self.hashval[i] <<= 8 - bits;
                if (i + 1) < c * (w / 8) {
                    self.hashval[i] |= self.hashval[i + 1] >> bits;
                }
            }
        }
    }

    pub fn finalize(&mut self, hashval: &mut Vec<u8>) {
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

        if hashval.is_empty() {
            hashval.extend(&self.hashval);
        }

        self.compute_hex_hashval();

        self.finalized = true;
    }
}

fn get_Q(wq: usize) -> Vec<md6_word> {
    let mut Q = Vec::new();
    if wq == 64 {
        Q = vec![
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
        ];
    } else if wq == 32 {
        Q = vec![
            0x7311c281, 0x2425cfa0, 0x64322864, 0x34aac8e7, 0xb60450e9, 0xef68b7c1, 0xe8fb2390,
            0x8d9f06f1, 0xdd2e76cb, 0xa691e5bf, 0x0cd0d63b, 0x2c30bc41, 0x1f8ccf68, 0x23058f8a,
            0x54e5ed5b, 0x88e3775d, 0x4ad12aae, 0x0a6d6031, 0x3e7f16bb, 0x88222e0d, 0x8af8671d,
            0x3fb50c2c, 0x995ad117, 0x8bd25c31, 0xc878c1dd, 0x04c4b633, 0x3b72066c, 0x7a1552ac,
            0x0d6f3522, 0x631effcb,
        ]
    } else if wq == 16 {
        Q = vec![
            0x7311, 0xc281, 0x2425, 0xcfa0, 0x6432, 0x2864, 0x34aa, 0xc8e7, 0xb604, 0x50e9, 0xef68,
            0xb7c1, 0xe8fb, 0x2390, 0x8d9f, 0x06f1, 0xdd2e, 0x76cb, 0xa691, 0xe5bf, 0x0cd0, 0xd63b,
            0x2c30, 0xbc41, 0x1f8c, 0xcf68, 0x2305, 0x8f8a, 0x54e5, 0xed5b, 0x88e3, 0x775d, 0x4ad1,
            0x2aae, 0x0a6d, 0x6031, 0x3e7f, 0x16bb, 0x8822, 0x2e0d, 0x8af8, 0x671d, 0x3fb5, 0x0c2c,
            0x995a, 0xd117, 0x8bd2, 0x5c31, 0xc878, 0xc1dd, 0x04c4, 0xb633, 0x3b72, 0x066c, 0x7a15,
            0x52ac, 0x0d6f, 0x3522, 0x631e, 0xffcb,
        ]
    } else if w == 8 {
        Q = vec![
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
    }

    Q
}

fn append_bits(dest: &mut Vec<u64>, destlen: usize, src: &[u8], srclen: usize) {
    if srclen == 0 {
        return;
    }

    let mut accum: u16 = 0; // Accumulates bits waiting to be moved, right-justified
    let mut accumlen = 0; // Number of bits in accumulator

    // Initialize accum, accumlen, and destination index (di)
    if destlen % 8 != 0 {
        accumlen = destlen % 8;
        accum = dest[destlen / 8] as u16; // Grab partial byte from dest
        accum >>= 8 - accumlen; // Right-justify it in accumulator
    }
    let mut di = destlen / 8; // Index of where next byte will go within dest

    // Ensure dest has enough space
    let new_len = (destlen + srclen + 7) / 8;
    if dest.len() < new_len {
        dest.resize(new_len, 0);
    }

    // Number of bytes (full or partial) in src
    let srcbytes = (srclen + 7) / 8;

    for i in 0..srcbytes {
        if i != srcbytes - 1 {
            // Not the last byte
            accum = (accum << 8) | src[i] as u16;
            accumlen += 8;
        } else {
            // Last byte
            let newbits = if srclen % 8 == 0 { 8 } else { srclen % 8 };
            accum = (accum << newbits) | ((src[i] as u16) >> (8 - newbits));
            accumlen += newbits;
        }

        // Process as many high-order bits of accum as possible
        while (i != srcbytes - 1 && accumlen >= 8) || (i == srcbytes - 1 && accumlen > 0) {
            let numbits = std::cmp::min(8, accumlen);
            let mut bits = (accum >> (accumlen - numbits)) as u16; // Right justified
            bits <<= 8 - numbits; // Left justified
            bits &= 0xff00 >> numbits; // Mask
            let bits = bits as u8;
            dest[di] = bits as u64; // Save
            di += 1;
            accumlen -= numbits;
        }
    }
}


fn md6_default_r(d: usize, keylen: usize) -> usize {
    // Default number of rounds is forty plus floor(d/4)
    let mut r = 40 + (d / 4);

    // unless keylen > 0, in which case it must be >= 80 as well
    if keylen > 0 {
        r = 80.max(r);
    }

    r
}

fn bytes_to_words(bytes: &[u8]) -> Vec<u64> {
    // Convert bytes to words
    bytes
        .chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .rev()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte))
        })
        .collect()
}

fn words_to_bytes(words: &[u64]) -> Vec<u8> {
    // Convert words to bytes
    words
        .iter()
        .flat_map(|&word| (0..8).rev().map(move |shift| (word >> (shift * 8)) as u8))
        .collect()
}

pub fn md6_full_hash(
    d: usize,
    data: Vec<u8>,
    databitlen: usize,
    key: Option<Vec<u8>>,
    keylen: usize,
    L: usize,
    r: usize,
    hashval: &mut Vec<u8>,
) {
    let mut st = MD6State::full_init(d, key, keylen, L, r);
    st.update(data, databitlen);
    st.finalize(hashval);
}

pub fn md6_hash(d: usize, data: Vec<u8>, databitlen: usize, hashval: &mut Vec<u8>) {
    md6_full_hash(
        d,
        data,
        databitlen,
        None,
        0,
        md6_default_L,
        md6_default_r(d, 0),
        hashval,
    );
}

#[test]
fn test_md6() {
    // Test from https://web.archive.org/web/20170812072847/https://groups.csail.mit.edu/cis/md6/submitted-2008-10-27/Supporting_Documentation/md6_report.pdf
    let test_vector: [(&str, usize, Option<Vec<u8>>, usize, usize, usize, &str); 1] = [
        (
            "abc",
            256,
            None,
            0,
            md6_default_L,
            5,
            "8854c14dc284f840ed71ad7ba542855ce189633e48c797a55121a746be48cec8",
        ),
    ];

    for (msg, hashbitlen, key, keylen, L, r, expected_hex) in test_vector {
        let mut output = vec![];

        md6_full_hash(
            hashbitlen,
            msg.as_bytes().to_vec(),
            msg.as_bytes().len() * 8,
            key,
            keylen,
            L,
            r,
            &mut output,
        );

        let digest_hex = output[..hashbitlen / 8]
            .into_iter()
            .map(|o| format!("{:02x}", o))
            .collect::<String>();

        assert_eq!(digest_hex, expected_hex);
    }
}
