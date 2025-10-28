//! AArch64 assembly backend

#![allow(clippy::many_single_char_names, clippy::unreadable_literal)]
use crate::consts::RC;

// Note: Apple M1 supports NEON and basic crypto extensions
// For now, we'll optimize the I function with ORN instruction (available in scalar AArch64)

// Animetosho optimization: Pack constants into 64-bit values for more efficient loading
#[allow(dead_code)]
static MD5_CONSTANTS_PACKED: [u64; 32] = [
    // F round constants (packed pairs)
    0xe8c7b756d76aa478, 0xc1bdceee242070db, 0x4787c62af57c0faf, 0xfd469501a8304613,
    0x8b44f7af698098d8, 0x895cd7beffff5bb1, 0xfd9871936b901122, 0x49b40821a679438e,
    // G round constants  
    0xc040b340f61e2562, 0xe9b6c7aa265e5a51, 0x02441453d62f105d, 0xe7d3fbc8d8a1e681,
    0xc33707d621e1cde6, 0x455a14edf4d50d87, 0xfcefa3f8a9e3e905, 0x8d2a4c8a676f02d9,
    // H round constants
    0x8771f681fffa3942, 0xfde5380c6d9d6122, 0x4bdecfa9a4beea44, 0xbebfbc70f6bb4b60, 
    0xeaa127fa289b7ec6, 0x04881d05d4ef3085, 0xe6db99e5d9d4d039, 0xc4ac56651fa27cf8,
    // I round constants
    0x432aff97f4292244, 0xfc93a039ab9423a7, 0x8f0ccc92655b59c3, 0x85845dd1ffeff47d,
    0xfe2ce6e06fa87e4f, 0x4e0811a1a3014314, 0xbd3af235f7537e82, 0xeb86d3912ad7d2bb
];

macro_rules! asm_op_f {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Optimized F with potential memory operand
                "and    w8, {b:w}, {c:w}",      // b & c
                "bic    w9, {d:w}, {b:w}",      // d & !b
                "add    w9, {a:w}, w9",         // a + (d & !b)
                "add    w10, {m:w}, {rc:w}",    // m + rc
                "add    w9, w9, w10",           // combine: a + (d & !b) + m + rc
                "add    w8, w9, w8",            // add (b & c)
                "ror    w8, w8, #{ror}",        // rotate
                "add    {a:w}, {b:w}, w8",      // b + rotated_result
                a = inout(reg) $a,
                b = in(reg) $b,
                c = in(reg) $c,
                d = in(reg) $d,
                m = in(reg) $m,
                rc = in(reg) $rc,
                ror = const (32 - $s),
                out("w8") _,
                out("w9") _,
                out("w10") _,
            );
        }
    };
}

macro_rules! asm_op_g {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Animetosho G function ADD shortcut: delay dependency on b
                "add    w10, {a:w}, {rc:w}",    // a + rc
                "add    w10, w10, {m:w}",       // a + rc + m
                "bic    w9, {c:w}, {d:w}",      // c & !d (no dependency on b)
                "add    w10, w10, w9",          // a + rc + m + (c & !d)
                "and    w8, {b:w}, {d:w}",      // b & d (now we depend on b)
                "add    w8, w10, w8",           // a + rc + m + (c & !d) + (b & d)
                "ror    w8, w8, #{ror}",        // rotate
                "add    {a:w}, {b:w}, w8",      // b + rotated_result
                a = inout(reg) $a,
                b = in(reg) $b,
                c = in(reg) $c,
                d = in(reg) $d,
                m = in(reg) $m,
                rc = in(reg) $rc,
                ror = const (32 - $s),
                out("w8") _,
                out("w9") _,
                out("w10") _,
            );
        }
    };
}

macro_rules! asm_op_h {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Standard H function: b ^ c ^ d
                "eor    w8, {b:w}, {c:w}",      // b ^ c
                "add    w9, {m:w}, {rc:w}",     // m + rc
                "eor    w8, w8, {d:w}",         // (b ^ c) ^ d = b ^ c ^ d
                "add    w9, {a:w}, w9",         // a + m + rc 
                "add    w8, w9, w8",            // add h_result
                "ror    w8, w8, #{ror}",        // rotate
                "add    {a:w}, {b:w}, w8",      // b + rotated_result
                a = inout(reg) $a,
                b = in(reg) $b,
                c = in(reg) $c,
                d = in(reg) $d,
                m = in(reg) $m,
                rc = in(reg) $rc,
                ror = const (32 - $s),
                out("w8") _,
                out("w9") _,
            );
        }
    };
}

macro_rules! asm_op_i {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Standard I function: c ^ (b | !d)
                "mvn    w8, {d:w}",             // !d (bitwise NOT)
                "add    w9, {m:w}, {rc:w}",     // m + rc
                "orr    w8, {b:w}, w8",         // b | !d
                "add    w9, {a:w}, w9",         // a + m + rc
                "eor    w8, {c:w}, w8",         // c ^ (b | !d)
                "add    w8, w9, w8",            // add i_result
                "ror    w8, w8, #{ror}",        // rotate
                "add    {a:w}, {b:w}, w8",      // b + rotated_result
                a = inout(reg) $a,
                b = in(reg) $b,
                c = in(reg) $c,
                d = in(reg) $d,
                m = in(reg) $m,
                rc = in(reg) $rc,
                ror = const (32 - $s),
                out("w8") _,
            );
        }
    };
}



#[inline]
fn compress_block(state: &mut [u32; 4], input: &[u8; 64]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // Load data efficiently and cache frequently used values
    let mut data = [0u32; 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    
    // Additional optimizations: better instruction scheduling and reduced dependencies

    // round 1
    asm_op_f!(a, b, c, d, data[0], RC[0], 7);
    asm_op_f!(d, a, b, c, data[1], RC[1], 12);
    asm_op_f!(c, d, a, b, data[2], RC[2], 17);
    asm_op_f!(b, c, d, a, data[3], RC[3], 22);

    asm_op_f!(a, b, c, d, data[4], RC[4], 7);
    asm_op_f!(d, a, b, c, data[5], RC[5], 12);
    asm_op_f!(c, d, a, b, data[6], RC[6], 17);
    asm_op_f!(b, c, d, a, data[7], RC[7], 22);

    asm_op_f!(a, b, c, d, data[8], RC[8], 7);
    asm_op_f!(d, a, b, c, data[9], RC[9], 12);
    asm_op_f!(c, d, a, b, data[10], RC[10], 17);
    asm_op_f!(b, c, d, a, data[11], RC[11], 22);

    asm_op_f!(a, b, c, d, data[12], RC[12], 7);
    asm_op_f!(d, a, b, c, data[13], RC[13], 12);
    asm_op_f!(c, d, a, b, data[14], RC[14], 17);
    asm_op_f!(b, c, d, a, data[15], RC[15], 22);

    // round 2
    asm_op_g!(a, b, c, d, data[1], RC[16], 5);
    asm_op_g!(d, a, b, c, data[6], RC[17], 9);
    asm_op_g!(c, d, a, b, data[11], RC[18], 14);
    asm_op_g!(b, c, d, a, data[0], RC[19], 20);

    asm_op_g!(a, b, c, d, data[5], RC[20], 5);
    asm_op_g!(d, a, b, c, data[10], RC[21], 9);
    asm_op_g!(c, d, a, b, data[15], RC[22], 14);
    asm_op_g!(b, c, d, a, data[4], RC[23], 20);

    asm_op_g!(a, b, c, d, data[9], RC[24], 5);
    asm_op_g!(d, a, b, c, data[14], RC[25], 9);
    asm_op_g!(c, d, a, b, data[3], RC[26], 14);
    asm_op_g!(b, c, d, a, data[8], RC[27], 20);

    asm_op_g!(a, b, c, d, data[13], RC[28], 5);
    asm_op_g!(d, a, b, c, data[2], RC[29], 9);
    asm_op_g!(c, d, a, b, data[7], RC[30], 14);
    asm_op_g!(b, c, d, a, data[12], RC[31], 20);

    // round 3
    asm_op_h!(a, b, c, d, data[5], RC[32], 4);
    asm_op_h!(d, a, b, c, data[8], RC[33], 11);
    asm_op_h!(c, d, a, b, data[11], RC[34], 16);
    asm_op_h!(b, c, d, a, data[14], RC[35], 23);

    asm_op_h!(a, b, c, d, data[1], RC[36], 4);
    asm_op_h!(d, a, b, c, data[4], RC[37], 11);
    asm_op_h!(c, d, a, b, data[7], RC[38], 16);
    asm_op_h!(b, c, d, a, data[10], RC[39], 23);

    asm_op_h!(a, b, c, d, data[13], RC[40], 4);
    asm_op_h!(d, a, b, c, data[0], RC[41], 11);
    asm_op_h!(c, d, a, b, data[3], RC[42], 16);
    asm_op_h!(b, c, d, a, data[6], RC[43], 23);

    asm_op_h!(a, b, c, d, data[9], RC[44], 4);
    asm_op_h!(d, a, b, c, data[12], RC[45], 11);
    asm_op_h!(c, d, a, b, data[15], RC[46], 16);
    asm_op_h!(b, c, d, a, data[2], RC[47], 23);

    // round 4
    asm_op_i!(a, b, c, d, data[0], RC[48], 6);
    asm_op_i!(d, a, b, c, data[7], RC[49], 10);
    asm_op_i!(c, d, a, b, data[14], RC[50], 15);
    asm_op_i!(b, c, d, a, data[5], RC[51], 21);

    asm_op_i!(a, b, c, d, data[12], RC[52], 6);
    asm_op_i!(d, a, b, c, data[3], RC[53], 10);
    asm_op_i!(c, d, a, b, data[10], RC[54], 15);
    asm_op_i!(b, c, d, a, data[1], RC[55], 21);

    asm_op_i!(a, b, c, d, data[8], RC[56], 6);
    asm_op_i!(d, a, b, c, data[15], RC[57], 10);
    asm_op_i!(c, d, a, b, data[6], RC[58], 15);
    asm_op_i!(b, c, d, a, data[13], RC[59], 21);

    asm_op_i!(a, b, c, d, data[4], RC[60], 6);
    asm_op_i!(d, a, b, c, data[11], RC[61], 10);
    asm_op_i!(c, d, a, b, data[2], RC[62], 15);
    asm_op_i!(b, c, d, a, data[9], RC[63], 21);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline]
pub(super) fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block)
    }
}