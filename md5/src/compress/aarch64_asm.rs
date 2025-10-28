//! AArch64 assembly backend

#![allow(clippy::many_single_char_names, clippy::unreadable_literal)]
use crate::consts::RC;

// Note: Apple M1 supports NEON and basic crypto extensions
// For now, we'll optimize the I function with ORN instruction (available in scalar AArch64)

// Animetosho optimization: Pack constants into 64-bit values for more efficient loading
#[allow(dead_code)]
static MD5_CONSTANTS_PACKED: [u64; 32] = [
    // F round constants (packed pairs)
    0xe8c7b756d76aa478,
    0xc1bdceee242070db,
    0x4787c62af57c0faf,
    0xfd469501a8304613,
    0x8b44f7af698098d8,
    0x895cd7beffff5bb1,
    0xfd9871936b901122,
    0x49b40821a679438e,
    // G round constants
    0xc040b340f61e2562,
    0xe9b6c7aa265e5a51,
    0x02441453d62f105d,
    0xe7d3fbc8d8a1e681,
    0xc33707d621e1cde6,
    0x455a14edf4d50d87,
    0xfcefa3f8a9e3e905,
    0x8d2a4c8a676f02d9,
    // H round constants
    0x8771f681fffa3942,
    0xfde5380c6d9d6122,
    0x4bdecfa9a4beea44,
    0xbebfbc70f6bb4b60,
    0xeaa127fa289b7ec6,
    0x04881d05d4ef3085,
    0xe6db99e5d9d4d039,
    0xc4ac56651fa27cf8,
    // I round constants
    0x432aff97f4292244,
    0xfc93a039ab9423a7,
    0x8f0ccc92655b59c3,
    0x85845dd1ffeff47d,
    0xfe2ce6e06fa87e4f,
    0x4e0811a1a3014314,
    0xbd3af235f7537e82,
    0xeb86d3912ad7d2bb,
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
                // Optimized H function: delay b dependency for better scheduling
                "add    w9, {m:w}, {rc:w}",     // m + rc first (no b dependency)
                "eor    w8, {c:w}, {d:w}",      // c ^ d first (no b dependency)
                "add    w9, {a:w}, w9",         // a + m + rc
                "eor    w8, w8, {b:w}",         // (c ^ d) ^ b = b ^ c ^ d (delay b use)
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

// Animetosho H function re-use optimization: eliminates MOV instructions
macro_rules! asm_op_h_reuse {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr, $tmp:ident) => {
        unsafe {
            core::arch::asm!(
                // H function with re-use: tmp should contain c^d from previous round
                "add    w9, {m:w}, {rc:w}",     // m + rc first (no b dependency)
                "eor    {tmp:w}, {tmp:w}, {b:w}", // reuse: tmp (c^d) ^ b = b^c^d
                "add    w9, {a:w}, w9",         // a + m + rc
                "add    w8, w9, {tmp:w}",       // add h_result
                "eor    {tmp:w}, {tmp:w}, {d:w}", // prepare for next: (b^c^d) ^ d = b^c
                "ror    w8, w8, #{ror}",        // rotate
                "add    {a:w}, {b:w}, w8",      // b + rotated_result
                a = inout(reg) $a,
                b = in(reg) $b,
                d = in(reg) $d,
                m = in(reg) $m,
                rc = in(reg) $rc,
                tmp = inout(reg) $tmp,
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
                // Optimized I function: use ORN (OR-NOT) instruction
                "orn    w8, {b:w}, {d:w}",      // b | !d in one instruction (ORN)
                "add    w9, {m:w}, {rc:w}",     // m + rc in parallel
                "eor    w8, {c:w}, w8",         // c ^ (b | !d)
                "add    w9, {a:w}, w9",         // a + m + rc
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

// 4-round macros for better instruction scheduling and organization
macro_rules! rf4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m0:expr, $m1:expr, $m2:expr, $m3:expr, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr) => {
        asm_op_f!($a, $b, $c, $d, $m0, $rc0, 7);
        asm_op_f!($d, $a, $b, $c, $m1, $rc1, 12);
        asm_op_f!($c, $d, $a, $b, $m2, $rc2, 17);
        asm_op_f!($b, $c, $d, $a, $m3, $rc3, 22);
    };
}

macro_rules! rg4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m0:expr, $m1:expr, $m2:expr, $m3:expr, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr) => {
        asm_op_g!($a, $b, $c, $d, $m0, $rc0, 5);
        asm_op_g!($d, $a, $b, $c, $m1, $rc1, 9);
        asm_op_g!($c, $d, $a, $b, $m2, $rc2, 14);
        asm_op_g!($b, $c, $d, $a, $m3, $rc3, 20);
    };
}

macro_rules! rh4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m0:expr, $m1:expr, $m2:expr, $m3:expr, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr, $tmp:ident) => {
        asm_op_h_reuse!($a, $b, $c, $d, $m0, $rc0, 4, $tmp);
        asm_op_h_reuse!($d, $a, $b, $c, $m1, $rc1, 11, $tmp);
        asm_op_h_reuse!($c, $d, $a, $b, $m2, $rc2, 16, $tmp);
        asm_op_h_reuse!($b, $c, $d, $a, $m3, $rc3, 23, $tmp);
    };
}

macro_rules! ri4 {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m0:expr, $m1:expr, $m2:expr, $m3:expr, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr) => {
        asm_op_i!($a, $b, $c, $d, $m0, $rc0, 6);
        asm_op_i!($d, $a, $b, $c, $m1, $rc1, 10);
        asm_op_i!($c, $d, $a, $b, $m2, $rc2, 15);
        asm_op_i!($b, $c, $d, $a, $m3, $rc3, 21);
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

    // Register caching optimization: cache ALL data values to eliminate memory accesses
    // Full cache array approach (animetosho Cache16 optimization)
    let cache0 = data[0];
    let cache1 = data[1];
    let cache2 = data[2];
    let cache3 = data[3];
    let cache4 = data[4];
    let cache5 = data[5];
    let cache6 = data[6];
    let cache7 = data[7];
    let cache8 = data[8];
    let cache9 = data[9];
    let cache10 = data[10];
    let cache11 = data[11];
    let cache12 = data[12];
    let cache13 = data[13];
    let cache14 = data[14];
    let cache15 = data[15];

    // Additional optimizations: better instruction scheduling and reduced dependencies

    // round 1 - first 4 operations with ldp constants optimization
    unsafe {
        core::arch::asm!(
            // Load first two constant pairs with ldp
            "ldp    {k0}, {k1}, [{const_ptr}]",  // Load RC[0,1] and RC[2,3] pairs
            // F0: a, b, c, d, data[0], RC[0], 7
            "and    w8, {b:w}, {c:w}",          // b & c
            "bic    w9, {d:w}, {b:w}",          // d & !b
            "add    w10, {data0:w}, {k0:w}",    // data[0] + RC[0] (lower 32 bits)
            "add    w9, {a:w}, w9",             // a + (d & !b)
            "add    w10, w9, w10",              // a + (d & !b) + data[0] + RC[0]
            "add    w8, w10, w8",               // add (b & c)
            "ror    w8, w8, #25",               // rotate by 32-7=25
            "add    {a:w}, {b:w}, w8",          // b + rotated -> new a

            // F1: d, a, b, c, cache1, RC[1], 12
            "and    w8, {a:w}, {b:w}",          // a & b (using updated a)
            "bic    w9, {c:w}, {a:w}",          // c & !a
            "lsr    {k0}, {k0}, #32",           // get RC[1] from upper 32 bits
            "add    w10, {data1:w}, {k0:w}",    // cache1 + RC[1]
            "add    w9, {d:w}, w9",             // d + (c & !a)
            "add    w10, w9, w10",              // d + (c & !a) + cache1 + RC[1]
            "add    w8, w10, w8",               // add (a & b)
            "ror    w8, w8, #20",               // rotate by 32-12=20
            "add    {d:w}, {a:w}, w8",          // a + rotated -> new d

            // F2: c, d, a, b, cache2, RC[2], 17
            "and    w8, {d:w}, {a:w}",          // d & a
            "bic    w9, {b:w}, {d:w}",          // b & !d
            "add    w10, {data2:w}, {k1:w}",    // cache2 + RC[2] (lower 32 bits)
            "add    w9, {c:w}, w9",             // c + (b & !d)
            "add    w10, w9, w10",              // c + (b & !d) + cache2 + RC[2]
            "add    w8, w10, w8",               // add (d & a)
            "ror    w8, w8, #15",               // rotate by 32-17=15
            "add    {c:w}, {d:w}, w8",          // d + rotated -> new c

            // F3: b, c, d, a, cache3, RC[3], 22
            "and    w8, {c:w}, {d:w}",          // c & d
            "bic    w9, {a:w}, {c:w}",          // a & !c
            "lsr    {k1}, {k1}, #32",           // get RC[3] from upper 32 bits
            "add    w10, {data3:w}, {k1:w}",    // cache3 + RC[3]
            "add    w9, {b:w}, w9",             // b + (a & !c)
            "add    w10, w9, w10",              // b + (a & !c) + cache3 + RC[3]
            "add    w8, w10, w8",               // add (c & d)
            "ror    w8, w8, #10",               // rotate by 32-22=10
            "add    {b:w}, {c:w}, w8",          // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data0 = in(reg) cache0,
            data1 = in(reg) cache1,
            data2 = in(reg) cache2,
            data3 = in(reg) cache3,
            k0 = out(reg) _,
            k1 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w9") _,
            out("w10") _,
        );
    }

    // F rounds 4-12: use RF4 macro for better instruction scheduling
    rf4!(
        a, b, c, d, cache4, cache5, cache6, cache7, RC[4], RC[5], RC[6], RC[7]
    );
    rf4!(
        a, b, c, d, cache8, cache9, cache10, cache11, RC[8], RC[9], RC[10], RC[11]
    );
    rf4!(
        a, b, c, d, cache12, cache13, cache14, cache15, RC[12], RC[13], RC[14], RC[15]
    );

    // round 2 - first 4 G operations with ldp constants optimization
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #64]", // Load RC[16,17] and RC[18,19] pairs
            // G0: a, b, c, d, cache1, RC[16], 5
            "and    w8, {b:w}, {d:w}",          // b & d
            "bic    w9, {c:w}, {d:w}",          // c & !d
            "add    w10, {data1:w}, {k2:w}",    // cache1 + RC[16] (lower 32 bits)
            "add    w10, {a:w}, w10",           // a + cache1 + RC[16]
            "add    w10, w10, w9",              // a + cache1 + RC[16] + (c & !d)
            "add    w8, w10, w8",               // ADD shortcut: + (b & d)
            "ror    w8, w8, #27",               // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",          // b + rotated -> new a

            // G1: d, a, b, c, cache6, RC[17], 9
            "and    w8, {a:w}, {c:w}",          // a & c (using updated a)
            "bic    w9, {b:w}, {c:w}",          // b & !c
            "lsr    {k2}, {k2}, #32",           // get RC[17] from upper 32 bits
            "add    w10, {data6:w}, {k2:w}",    // cache6 + RC[17]
            "add    w10, {d:w}, w10",           // d + cache6 + RC[17]
            "add    w10, w10, w9",              // d + cache6 + RC[17] + (b & !c)
            "add    w8, w10, w8",               // ADD shortcut: + (a & c)
            "ror    w8, w8, #23",               // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",          // a + rotated -> new d

            // G2: c, d, a, b, cache11, RC[18], 14
            "and    w8, {d:w}, {b:w}",          // d & b
            "bic    w9, {a:w}, {b:w}",          // a & !b
            "add    w10, {data11:w}, {k3:w}",   // cache11 + RC[18] (lower 32 bits)
            "add    w10, {c:w}, w10",           // c + cache11 + RC[18]
            "add    w10, w10, w9",              // c + cache11 + RC[18] + (a & !b)
            "add    w8, w10, w8",               // ADD shortcut: + (d & b)
            "ror    w8, w8, #18",               // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",          // d + rotated -> new c

            // G3: b, c, d, a, data[0], RC[19], 20
            "and    w8, {c:w}, {a:w}",          // c & a
            "bic    w9, {d:w}, {a:w}",          // d & !a
            "lsr    {k3}, {k3}, #32",           // get RC[19] from upper 32 bits
            "add    w10, {data0:w}, {k3:w}",    // data[0] + RC[19]
            "add    w10, {b:w}, w10",           // b + data[0] + RC[19]
            "add    w10, w10, w9",              // b + data[0] + RC[19] + (d & !a)
            "add    w8, w10, w8",               // ADD shortcut: + (c & a)
            "ror    w8, w8, #12",               // rotate by 32-20=12
            "add    {b:w}, {c:w}, w8",          // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data1 = in(reg) cache1,
            data6 = in(reg) cache6,
            data11 = in(reg) cache11,
            data0 = in(reg) cache0,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w9") _,
            out("w10") _,
        );
    }

    // G rounds 20-32: use RG4 macro for better instruction scheduling
    rg4!(
        a, b, c, d, cache5, cache10, cache15, cache4, RC[20], RC[21], RC[22], RC[23]
    );
    rg4!(
        a, b, c, d, cache9, cache14, cache3, cache8, RC[24], RC[25], RC[26], RC[27]
    );
    rg4!(
        a, b, c, d, cache13, cache2, cache7, cache12, RC[28], RC[29], RC[30], RC[31]
    );

    // round 3 - H function with re-use optimization (animetosho technique)
    // Initialize tmp register for H function re-use
    #[allow(unused_assignments)] // Last H reuse writes tmp_h but it's not used after
    let mut tmp_h: u32;
    unsafe {
        // Initialize tmp with c^d for first H round
        core::arch::asm!(
            "eor {tmp:w}, {c:w}, {d:w}",
            tmp = out(reg) tmp_h,
            c = in(reg) c,
            d = in(reg) d,
        );
    }

    // H rounds 32-48: use RH4 macro for better instruction scheduling
    // Note: H rounds use reuse optimization for rounds 32-43, regular H for rounds 44-47
    rh4!(
        a, b, c, d, cache5, cache8, cache11, cache14, RC[32], RC[33], RC[34], RC[35], tmp_h
    );
    rh4!(
        a, b, c, d, cache1, cache4, cache7, cache10, RC[36], RC[37], RC[38], RC[39], tmp_h
    );
    #[allow(unused_assignments)] // Last RH4 reuse writes tmp_h but it's not used after
    {
        rh4!(
            a, b, c, d, cache13, cache0, cache3, cache6, RC[40], RC[41], RC[42], RC[43], tmp_h
        );
    }
    // Last 4 H rounds use regular asm_op_h! not reuse
    asm_op_h!(a, b, c, d, cache9, RC[44], 4);
    asm_op_h!(d, a, b, c, cache12, RC[45], 11);
    asm_op_h!(c, d, a, b, cache15, RC[46], 16);
    asm_op_h!(b, c, d, a, cache2, RC[47], 23);

    // I rounds 48-64: use RI4 macro for better instruction scheduling
    ri4!(
        a, b, c, d, cache0, cache7, cache14, cache5, RC[48], RC[49], RC[50], RC[51]
    );
    ri4!(
        a, b, c, d, cache12, cache3, cache10, cache1, RC[52], RC[53], RC[54], RC[55]
    );
    ri4!(
        a, b, c, d, cache8, cache15, cache6, cache13, RC[56], RC[57], RC[58], RC[59]
    );
    ri4!(
        a, b, c, d, cache4, cache11, cache2, cache9, RC[60], RC[61], RC[62], RC[63]
    );

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
