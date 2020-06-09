//! Experimental pure Rust implementation of the KangarooTwelve
//! cryptographic hash algorithm, based on the reference implementation:
//!
//! <https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/kangaroo_twelve-reference/K12.py>
//!
//! Some optimisations copied from: <https://github.com/RustCrypto/hashes/tree/master/sha3/src>

// Based off this translation originally by Diggory Hardy:
// <https://github.com/dhardy/hash-bench/blob/master/src/k12.rs>

#![no_std]
#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

// TODO(tarcieri): eliminate alloc requirement
#[macro_use]
extern crate alloc;

pub use digest;

#[macro_use]
mod lanes;

// TODO(tarcieri): eliminate usage of `Vec`
use alloc::vec::Vec;
use core::{cmp::min, convert::TryInto, mem};
use digest::{ExtendableOutputDirty, Reset, Update, XofReader};

/// The KangarooTwelve extendable-output function (XOF).
#[derive(Debug, Default)]
pub struct KangarooTwelve {
    /// Input to be processed
    // TODO(tarcieri): don't store input in a `Vec`
    buffer: Vec<u8>,

    /// Customization string to apply
    // TODO(tarcieri): don't store customization in a `Vec`
    customization: Vec<u8>,
}

impl KangarooTwelve {
    /// Create a new [`KangarooTwelve`] instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new [`KangarooTwelve`] instance with the given customization.
    pub fn new_with_customization(customization: impl AsRef<[u8]>) -> Self {
        Self {
            buffer: Vec::new(),
            customization: customization.as_ref().into(),
        }
    }
}

impl Update for KangarooTwelve {
    /// Input data into the hash function
    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.buffer.extend_from_slice(bytes.as_ref());
    }
}

impl ExtendableOutputDirty for KangarooTwelve {
    type Reader = Reader;

    fn finalize_xof_dirty(&mut self) -> Self::Reader {
        let mut buffer = vec![];
        let mut customization = vec![];

        mem::swap(&mut self.buffer, &mut buffer);
        mem::swap(&mut self.customization, &mut customization);

        Reader {
            buffer,
            customization,
            finished: false,
        }
    }
}

impl Reset for KangarooTwelve {
    fn reset(&mut self) {
        self.buffer.clear();
    }
}

/// Extensible output reader.
///
/// NOTE: this presently only supports one invocation and will *panic* if
/// [`XofReader::read`] is invoked on it multiple times.
#[derive(Debug, Default)]
pub struct Reader {
    /// Input to be processed
    // TODO(tarcieri): don't store input in a `Vec`
    buffer: Vec<u8>,

    /// Customization string to apply
    // TODO(tarcieri): don't store customization in a `Vec`
    customization: Vec<u8>,

    /// Has the XOF output already been consumed?
    // TODO(tarcieri): allow `XofReader::result` to be called multiple times
    finished: bool,
}

// TODO(tarcieri): factor more of this logic into the `KangarooTwelve` type
impl XofReader for Reader {
    /// Get the resulting output of the function.
    ///
    /// Panics if called multiple times on the same instance (TODO: don't panic!)
    fn read(&mut self, output: &mut [u8]) {
        assert!(
            !self.finished,
            "not yet implemented: multiple XofReader::read invocations unsupported"
        );

        let b = 8192;
        let c = 256;

        let mut slice = Vec::new(); // S
        slice.extend_from_slice(&self.buffer);
        slice.extend_from_slice(&self.customization);
        slice.extend_from_slice(&right_encode(self.customization.len())[..]);

        // === Cut the input string into chunks of b bytes ===
        let n = (slice.len() + b - 1) / b;
        let mut slices = Vec::with_capacity(n); // Si
        for i in 0..n {
            let ub = min((i + 1) * b, slice.len());
            slices.push(&slice[i * b..ub]);
        }

        // TODO(tarcieri): get rid of intermediate output buffer
        let tmp_buffer = if n == 1 {
            // === Process the tree with only a final node ===
            f(slices[0], 0x07, output.len())
        } else {
            // === Process the tree with kangaroo hopping ===
            // TODO: in parallel
            let mut intermediate = Vec::with_capacity(n - 1); // CVi
            for i in 0..n - 1 {
                intermediate.push(f(slices[i + 1], 0x0B, c / 8));
            }

            let mut node_star = Vec::new();
            node_star.extend_from_slice(slices[0]);
            node_star.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0, 0]);

            #[allow(clippy::needless_range_loop)]
            for i in 0..n - 1 {
                node_star.extend_from_slice(&intermediate[i][..]);
            }

            node_star.extend_from_slice(&right_encode(n - 1));
            node_star.extend_from_slice(b"\xFF\xFF");

            f(&node_star[..], 0x06, output.len())
        };

        output.copy_from_slice(&tmp_buffer);
        self.finished = true;
    }
}

fn f(input: &[u8], suffix: u8, mut output_len: usize) -> Vec<u8> {
    let mut state = [0u8; 200];
    let max_block_size = 1344 / 8; // r, also known as rate in bytes

    // === Absorb all the input blocks ===
    // We unroll first loop, which allows simple copy
    let mut block_size = min(input.len(), max_block_size);
    state[0..block_size].copy_from_slice(&input[0..block_size]);

    let mut offset = block_size;
    while offset < input.len() {
        keccak(&mut state);
        block_size = min(input.len() - offset, max_block_size);
        for i in 0..block_size {
            // TODO: is this sufficiently optimisable or better to convert to u64 first?
            state[i] ^= input[i + offset];
        }
        offset += block_size;
    }
    if block_size == max_block_size {
        // TODO: condition is nearly always false; tests pass without this.
        // Why is it here?
        keccak(&mut state);
        block_size = 0;
    }

    // === Do the padding and switch to the squeezing phase ===
    state[block_size] ^= suffix;
    if ((suffix & 0x80) != 0) && (block_size == (max_block_size - 1)) {
        // TODO: condition is almost always false — in fact tests pass without
        // this block! So why is it here?
        keccak(&mut state);
    }
    state[max_block_size - 1] ^= 0x80;
    keccak(&mut state);

    // === Squeeze out all the output blocks ===
    let mut output = Vec::with_capacity(output_len);
    while output_len > 0 {
        block_size = min(output_len, max_block_size);
        output.extend_from_slice(&state[0..block_size]);
        output_len -= block_size;
        if output_len > 0 {
            keccak(&mut state);
        }
    }
    output
}

fn keccak(state: &mut [u8; 200]) {
    let mut lanes = [0u64; 25];
    let mut y;
    for x in 0..5 {
        FOR5!(y, 5, {
            let pos = 8 * (x + y);
            lanes[x + y] = u64::from_le_bytes(state[pos..(pos + 8)].try_into().unwrap());
        });
    }
    lanes::keccak(&mut lanes);
    for x in 0..5 {
        FOR5!(y, 5, {
            let i = 8 * (x + y);
            state[i..i + 8].copy_from_slice(&lanes[x + y].to_le_bytes());
        });
    }
}

fn right_encode(mut x: usize) -> Vec<u8> {
    let mut slice = Vec::new();
    while x > 0 {
        slice.push((x % 256) as u8);
        x /= 256;
    }
    slice.reverse();
    let len = slice.len();
    slice.push(len as u8);
    slice
}
