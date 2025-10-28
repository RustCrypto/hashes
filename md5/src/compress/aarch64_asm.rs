//! AArch64 assembly backend

#![allow(clippy::many_single_char_names, clippy::unreadable_literal)]
use crate::consts::RC;

// Note: Apple M1 supports NEON and basic crypto extensions
// For now, we'll optimize the I function with ORN instruction (available in scalar AArch64)

// Pack constants into 64-bit values for more efficient loading with ldp
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

macro_rules! asm_op_h {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Optimized H function: improve dependency chains
                "eor    w8, {c:w}, {d:w}",      // c ^ d first (independent)
                "add    w9, {m:w}, {rc:w}",     // m + rc in parallel
                "eor    w8, w8, {b:w}",         // (c ^ d) ^ b = b ^ c ^ d
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

// Integrated RH4 with H function reuse optimization and ldp constant loading
macro_rules! rh4_integrated {
    ($a:ident, $b:ident, $c:ident, $d:ident, $cache0:ident, $cache1:ident, $cache2:ident, $cache3:ident, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr, $const_ptr:expr, $offset:expr, $tmp:ident) => {
        unsafe {
            core::arch::asm!(
                // Load RC constant pairs with ldp for better throughput
                "ldp    x10, x11, [{const_ptr}, #{k_offset}]",    // Load RC pair

                // H round 0: A += H(B,C,D) + cache0 + RC[k]; A = rotl(A, 4) + B
                "eor    {tmp:w}, {tmp:w}, {b:w}",        // reuse: tmp (c^d) ^ b = b^c^d (independent first)
                "add    w9, {cache0:w}, w10",            // cache0 + RC[k0] (parallel)
                "lsr    x10, x10, #32",                  // shift for next constant (early)
                "add    w9, {a:w}, w9",                  // a + cache0 + RC[k0]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {d:w}",        // prepare for next: (b^c^d) ^ d = b^c
                "ror    w8, w8, #28",                    // rotate 32-4=28
                "add    {a:w}, {b:w}, w8",               // b + rotated_result

                // H round 1: D += H(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 11) + A
                "eor    {tmp:w}, {tmp:w}, {a:w}",        // reuse: tmp (b^c) ^ a = a^b^c (independent first)
                "add    w9, {cache1:w}, w10",            // cache1 + RC[k+1] (parallel)
                "add    w9, {d:w}, w9",                  // d + cache1 + RC[k+1]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {c:w}",        // prepare for next: (a^b^c) ^ c = a^b
                "ror    w8, w8, #21",                    // rotate 32-11=21
                "add    {d:w}, {a:w}, w8",               // a + rotated_result

                // H round 2: C += H(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 16) + D
                "eor    {tmp:w}, {tmp:w}, {d:w}",        // reuse: tmp (a^b) ^ d = d^a^b (independent first)
                "add    w9, {cache2:w}, w11",            // cache2 + RC[k+2] (parallel)
                "lsr    x11, x11, #32",                  // shift for next constant (early)
                "add    w9, {c:w}, w9",                  // c + cache2 + RC[k+2]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {b:w}",        // prepare for next: (d^a^b) ^ b = d^a
                "ror    w8, w8, #16",                    // rotate 32-16=16
                "add    {c:w}, {d:w}, w8",               // d + rotated_result

                // H round 3: B += H(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 23) + C
                "eor    {tmp:w}, {tmp:w}, {c:w}",        // reuse: tmp (d^a) ^ c = c^d^a (independent first)
                "add    w9, {cache3:w}, w11",            // cache3 + RC[k+3] (parallel)
                "add    w9, {b:w}, w9",                  // b + cache3 + RC[k+3]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {a:w}",        // prepare for next: (c^d^a) ^ a = c^d
                "ror    w8, w8, #9",                     // rotate 32-23=9
                "add    {b:w}, {c:w}, w8",               // c + rotated_result

                a = inout(reg) $a,
                b = inout(reg) $b,
                c = inout(reg) $c,
                d = inout(reg) $d,
                cache0 = in(reg) $cache0,
                cache1 = in(reg) $cache1,
                cache2 = in(reg) $cache2,
                cache3 = in(reg) $cache3,
                tmp = inout(reg) $tmp,
                const_ptr = in(reg) $const_ptr,
                k_offset = const $offset, // Byte offset for packed constants
                out("x10") _,
                out("x11") _,
                out("w8") _,
                out("w9") _,
            );
        }
    };
}

// Integrated RF4 with data and constant loading - loads from cache array like current approach
macro_rules! rf4_integrated {
    ($a:ident, $b:ident, $c:ident, $d:ident, $cache0:ident, $cache1:ident, $cache2:ident, $cache3:ident, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr, $const_ptr:expr, $offset:expr) => {
        unsafe {
            core::arch::asm!(
                // Load RC constant pairs with ldp for better throughput
                "ldp    x10, x11, [{const_ptr}, #{k_offset}]",    // Load RC pair

                // F round 0: A += F(B,C,D) + cache0 + RC[k]; A = rotl(A, 7) + B
                "eor    w12, {c:w}, {d:w}",              // c ^ d (independent F calc first)
                "add    w8, {a:w}, {cache0:w}",          // a + cache0 (use w8 to avoid dependency)
                "and    w12, w12, {b:w}",                // (c ^ d) & b (parallel)
                "add    w8, w8, w10",                    // add RC[k0] (parallel)
                "lsr    x10, x10, #32",                  // shift for next constant (early)
                "eor    w12, w12, {d:w}",                // F(b,c,d)
                "add    {a:w}, w8, w12",                 // combine all additions
                "ror    {a:w}, {a:w}, #25",              // rotate by 25 (optimized)
                "add    {a:w}, {a:w}, {b:w}",            // a += b

                // F round 1: D += F(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 12) + A
                "eor    w12, {b:w}, {c:w}",              // b ^ c (independent calc first)
                "add    w8, {d:w}, {cache1:w}",          // d + cache1 (use w8 to avoid dependency)
                "and    w12, w12, {a:w}",                // (b ^ c) & a (parallel)
                "add    w8, w8, w10",                    // add RC[k+1] (parallel)
                "eor    w12, w12, {c:w}",                // F(a,b,c)
                "add    {d:w}, w8, w12",                 // combine all additions
                "ror    {d:w}, {d:w}, #20",              // rotate by 20 (optimized)
                "add    {d:w}, {d:w}, {a:w}",            // d += a

                // F round 2: C += F(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 17) + D
                "eor    w12, {a:w}, {b:w}",              // a ^ b (independent calc first)
                "add    w9, {c:w}, {cache2:w}",          // c + cache2 (use w9 to avoid dependency)
                "and    w12, w12, {d:w}",                // (a ^ b) & d (parallel)
                "add    w9, w9, w11",                    // add RC[k+2] (parallel)
                "lsr    x11, x11, #32",                  // shift for next constant (early)
                "eor    w12, w12, {b:w}",                // F(d,a,b)
                "add    {c:w}, w9, w12",                 // combine all additions
                "ror    {c:w}, {c:w}, #15",              // rotate by 15 (optimized)
                "add    {c:w}, {c:w}, {d:w}",            // c += d

                // F round 3: B += F(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 22) + C
                "eor    w12, {d:w}, {a:w}",              // d ^ a (independent calc first)
                "add    w8, {b:w}, {cache3:w}",          // b + cache3 (use w8 to avoid dependency)
                "and    w12, w12, {c:w}",                // (d ^ a) & c (parallel)
                "add    w8, w8, w11",                    // add RC[k+3] (parallel)
                "eor    w12, w12, {a:w}",                // F(c,d,a)
                "add    {b:w}, w8, w12",                 // combine all additions
                "ror    {b:w}, {b:w}, #10",              // rotate by 10 (optimized)
                "add    {b:w}, {b:w}, {c:w}",            // b += c

                a = inout(reg) $a,
                b = inout(reg) $b,
                c = inout(reg) $c,
                d = inout(reg) $d,
                cache0 = in(reg) $cache0,
                cache1 = in(reg) $cache1,
                cache2 = in(reg) $cache2,
                cache3 = in(reg) $cache3,
                const_ptr = in(reg) $const_ptr,
                k_offset = const $offset, // Byte offset for packed constants
                out("x10") _,
                out("x11") _,
                out("w12") _,
            );
        }
    };
}

// Macro rg4_integrated removed - all G rounds now use optimized assembly blocks

// Integrated RI4 with alternative I function and ldp constant loading
macro_rules! ri4_integrated {
    ($a:ident, $b:ident, $c:ident, $d:ident, $cache0:ident, $cache1:ident, $cache2:ident, $cache3:ident, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr, $const_ptr:expr, $offset:expr) => {
        unsafe {
            core::arch::asm!(
                // Load RC constant pairs with ldp for better throughput
                "ldp    x10, x11, [{const_ptr}, #{k_offset}]",    // Load RC pair

                // I round 0: A += I(B,C,D) + cache0 + RC[k]; A = rotl(A, 6) + B
                "orn    w12, {b:w}, {d:w}",              // b | ~d (independent I function calc)
                "add    {a:w}, {a:w}, {cache0:w}",       // a += cache0 (parallel)
                "add    {a:w}, {a:w}, w10",              // a += RC[k0] (early)
                "eor    w12, w12, {c:w}",                // (b | ~d) ^ c = I(b,c,d)
                "lsr    x10, x10, #32",                  // shift for next constant (early)
                "add    {a:w}, {a:w}, w12",              // a += I(b,c,d)
                "ror    {a:w}, {a:w}, #26",              // rotate 32-6=26
                "add    {a:w}, {a:w}, {b:w}",            // a += b

                // I round 1: D += I(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 10) + A
                "orn    w12, {a:w}, {c:w}",              // a | ~c (independent I function calc)
                "add    w9, {d:w}, {cache1:w}",          // d + cache1 (use w9 to avoid dependency)
                "eor    w12, w12, {b:w}",                // (a | ~c) ^ b = I(a,b,c) (parallel)
                "add    w9, w9, w10",                    // add RC[k+1] (parallel)
                "add    {d:w}, w9, w12",                 // combine all additions
                "ror    {d:w}, {d:w}, #22",              // rotate 32-10=22
                "add    {d:w}, {d:w}, {a:w}",            // d += a

                // I round 2: C += I(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 15) + D
                "orn    w12, {d:w}, {b:w}",              // d | ~b (independent I function calc)
                "add    w8, {c:w}, {cache2:w}",          // c + cache2 (use w8 to avoid dependency)
                "eor    w12, w12, {a:w}",                // (d | ~b) ^ a = I(d,a,b) (parallel)
                "add    w8, w8, w11",                    // add RC[k+2] (parallel)
                "lsr    x11, x11, #32",                  // shift for next constant (early)
                "add    {c:w}, w8, w12",                 // combine all additions
                "ror    {c:w}, {c:w}, #17",              // rotate 32-15=17
                "add    {c:w}, {c:w}, {d:w}",            // c += d

                // I round 3: B += I(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 21) + C
                "orn    w12, {c:w}, {a:w}",              // c | ~a (independent I function calc)
                "add    w9, {b:w}, {cache3:w}",          // b + cache3 (use w9 to avoid dependency)
                "eor    w12, w12, {d:w}",                // (c | ~a) ^ d = I(c,d,a) (parallel)
                "add    w9, w9, w11",                    // add RC[k+3] (parallel)
                "add    {b:w}, w9, w12",                 // combine all additions
                "ror    {b:w}, {b:w}, #11",              // rotate 32-21=11
                "add    {b:w}, {b:w}, {c:w}",            // b += c

                a = inout(reg) $a,
                b = inout(reg) $b,
                c = inout(reg) $c,
                d = inout(reg) $d,
                cache0 = in(reg) $cache0,
                cache1 = in(reg) $cache1,
                cache2 = in(reg) $cache2,
                cache3 = in(reg) $cache3,
                const_ptr = in(reg) $const_ptr,
                k_offset = const $offset, // Byte offset for packed constants
                out("x10") _,
                out("x11") _,
                out("w12") _,
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

    // Optimized input data loading: use ldp to load data pairs directly
    // This eliminates the intermediate array and reduces memory bandwidth
    let mut cache0: u32;
    let mut cache1: u32;
    let mut cache2: u32;
    let mut cache3: u32;
    let mut cache4: u32;
    let mut cache5: u32;
    let mut cache6: u32;
    let mut cache7: u32;
    let mut cache8: u32;
    let mut cache9: u32;
    let mut cache10: u32;
    let mut cache11: u32;
    let mut cache12: u32;
    let mut cache13: u32;
    let mut cache14: u32;
    let mut cache15: u32;

    // Load all input data using ldp instructions for better memory bandwidth
    // Advanced optimization: direct ldp loading eliminates intermediate array
    unsafe {
        core::arch::asm!(
            // Load input data pairs with ldp - optimized addressing
            "ldp    {cache0:w}, {cache1:w}, [{input_ptr}, #0]",    // data[0], data[1]
            "ldp    {cache2:w}, {cache3:w}, [{input_ptr}, #8]",    // data[2], data[3]
            "ldp    {cache4:w}, {cache5:w}, [{input_ptr}, #16]",   // data[4], data[5]
            "ldp    {cache6:w}, {cache7:w}, [{input_ptr}, #24]",   // data[6], data[7]
            "ldp    {cache8:w}, {cache9:w}, [{input_ptr}, #32]",   // data[8], data[9]
            "ldp    {cache10:w}, {cache11:w}, [{input_ptr}, #40]", // data[10], data[11]
            "ldp    {cache12:w}, {cache13:w}, [{input_ptr}, #48]", // data[12], data[13]
            "ldp    {cache14:w}, {cache15:w}, [{input_ptr}, #56]", // data[14], data[15]
            input_ptr = in(reg) input.as_ptr(),
            cache0 = out(reg) cache0,
            cache1 = out(reg) cache1,
            cache2 = out(reg) cache2,
            cache3 = out(reg) cache3,
            cache4 = out(reg) cache4,
            cache5 = out(reg) cache5,
            cache6 = out(reg) cache6,
            cache7 = out(reg) cache7,
            cache8 = out(reg) cache8,
            cache9 = out(reg) cache9,
            cache10 = out(reg) cache10,
            cache11 = out(reg) cache11,
            cache12 = out(reg) cache12,
            cache13 = out(reg) cache13,
            cache14 = out(reg) cache14,
            cache15 = out(reg) cache15,
        );
    }

    // Optimized F rounds (0-7): Larger asm block for better cross-round optimization
    // Limited by Rust's register allocation but still better than individual macros
    unsafe {
        core::arch::asm!(
            // Load constants for F0-F7
            "ldp    x10, x11, [{kptr}]",        // RC[0,1] and RC[2,3]
            "ldp    x12, x13, [{kptr}, #16]",   // RC[4,5] and RC[6,7]

            // F0: A += F(B,C,D) + cache0 + RC[0]; A = rotl(A, 7) + B
            "eor    w8, {c:w}, {d:w}",          // c ^ d (F function start)
            "add    w9, {cache0:w}, w10",       // cache0 + RC[0] (parallel)
            "and    w8, w8, {b:w}",             // (c ^ d) & b
            "add    {a:w}, {a:w}, w9",          // a += cache0 + RC[0]
            "eor    w8, w8, {d:w}",             // F(b,c,d)
            "lsr    x10, x10, #32",             // prepare RC[1]
            "add    {a:w}, {a:w}, w8",          // a += F(b,c,d)
            "ror    {a:w}, {a:w}, #25",         // rotate 32-7=25
            "add    {a:w}, {a:w}, {b:w}",       // a += b

            // F1: D += F(A,B,C) + cache1 + RC[1]; D = rotl(D, 12) + A
            "eor    w8, {b:w}, {c:w}",          // b ^ c (start early with updated values)
            "add    w9, {cache1:w}, w10",       // cache1 + RC[1] (parallel)
            "and    w8, w8, {a:w}",             // (b ^ c) & a
            "add    {d:w}, {d:w}, w9",          // d += cache1 + RC[1]
            "eor    w8, w8, {c:w}",             // F(a,b,c)
            "add    {d:w}, {d:w}, w8",          // d += F(a,b,c)
            "ror    {d:w}, {d:w}, #20",         // rotate 32-12=20
            "add    {d:w}, {d:w}, {a:w}",       // d += a

            // F2: C += F(D,A,B) + cache2 + RC[2]; C = rotl(C, 17) + D
            "eor    w8, {a:w}, {b:w}",          // a ^ b (with updated a)
            "add    w9, {cache2:w}, w11",       // cache2 + RC[2] (parallel)
            "and    w8, w8, {d:w}",             // (a ^ b) & d
            "add    {c:w}, {c:w}, w9",          // c += cache2 + RC[2]
            "eor    w8, w8, {b:w}",             // F(d,a,b)
            "lsr    x11, x11, #32",             // prepare RC[3]
            "add    {c:w}, {c:w}, w8",          // c += F(d,a,b)
            "ror    {c:w}, {c:w}, #15",         // rotate 32-17=15
            "add    {c:w}, {c:w}, {d:w}",       // c += d

            // F3: B += F(C,D,A) + cache3 + RC[3]; B = rotl(B, 22) + C
            "eor    w8, {d:w}, {a:w}",          // d ^ a
            "add    w9, {cache3:w}, w11",       // cache3 + RC[3] (parallel)
            "and    w8, w8, {c:w}",             // (d ^ a) & c
            "add    {b:w}, {b:w}, w9",          // b += cache3 + RC[3]
            "eor    w8, w8, {a:w}",             // F(c,d,a)
            "add    {b:w}, {b:w}, w8",          // b += F(c,d,a)
            "ror    {b:w}, {b:w}, #10",         // rotate 32-22=10
            "add    {b:w}, {b:w}, {c:w}",       // b += c

            // F4: A += F(B,C,D) + cache4 + RC[4]; A = rotl(A, 7) + B
            "eor    w8, {c:w}, {d:w}",          // c ^ d
            "add    w9, {cache4:w}, w12",       // cache4 + RC[4]
            "and    w8, w8, {b:w}",             // (c ^ d) & b
            "add    {a:w}, {a:w}, w9",          // a += cache4 + RC[4]
            "eor    w8, w8, {d:w}",             // F(b,c,d)
            "lsr    x12, x12, #32",             // prepare RC[5]
            "add    {a:w}, {a:w}, w8",          // a += F(b,c,d)
            "ror    {a:w}, {a:w}, #25",         // rotate
            "add    {a:w}, {a:w}, {b:w}",       // a += b

            // F5: D += F(A,B,C) + cache5 + RC[5]; D = rotl(D, 12) + A
            "eor    w8, {b:w}, {c:w}",          // b ^ c
            "add    w9, {cache5:w}, w12",       // cache5 + RC[5]
            "and    w8, w8, {a:w}",             // (b ^ c) & a
            "add    {d:w}, {d:w}, w9",          // d += cache5 + RC[5]
            "eor    w8, w8, {c:w}",             // F(a,b,c)
            "add    {d:w}, {d:w}, w8",          // d += F(a,b,c)
            "ror    {d:w}, {d:w}, #20",         // rotate
            "add    {d:w}, {d:w}, {a:w}",       // d += a

            // F6: C += F(D,A,B) + cache6 + RC[6]; C = rotl(C, 17) + D
            "eor    w8, {a:w}, {b:w}",          // a ^ b
            "add    w9, {cache6:w}, w13",       // cache6 + RC[6]
            "and    w8, w8, {d:w}",             // (a ^ b) & d
            "add    {c:w}, {c:w}, w9",          // c += cache6 + RC[6]
            "eor    w8, w8, {b:w}",             // F(d,a,b)
            "lsr    x13, x13, #32",             // prepare RC[7]
            "add    {c:w}, {c:w}, w8",          // c += F(d,a,b)
            "ror    {c:w}, {c:w}, #15",         // rotate
            "add    {c:w}, {c:w}, {d:w}",       // c += d

            // F7: B += F(C,D,A) + cache7 + RC[7]; B = rotl(B, 22) + C
            "eor    w8, {d:w}, {a:w}",          // d ^ a
            "add    w9, {cache7:w}, w13",       // cache7 + RC[7]
            "and    w8, w8, {c:w}",             // (d ^ a) & c
            "add    {b:w}, {b:w}, w9",          // b += cache7 + RC[7]
            "eor    w8, w8, {a:w}",             // F(c,d,a)
            "add    {b:w}, {b:w}, w8",          // b += F(c,d,a)
            "ror    {b:w}, {b:w}, #10",         // rotate
            "add    {b:w}, {b:w}, {c:w}",       // b += c

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            cache0 = in(reg) cache0,
            cache1 = in(reg) cache1,
            cache2 = in(reg) cache2,
            cache3 = in(reg) cache3,
            cache4 = in(reg) cache4,
            cache5 = in(reg) cache5,
            cache6 = in(reg) cache6,
            cache7 = in(reg) cache7,
            kptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("x10") _, out("x11") _, out("x12") _, out("x13") _,
            out("w8") _, out("w9") _,
        );
    }

    // F rounds 8-11: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load F round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #32]", // Load RC[8,9] and RC[10,11] pairs
            // F8: a, b, c, d, cache8, RC[8], 7 - optimized scheduling
            "add    w10, {data8:w}, {k2:w}",     // cache8 + RC[8] (lower 32 bits) - early
            "eor    w8, {c:w}, {d:w}",           // c ^ d
            "add    w10, {a:w}, w10",            // a + cache8 + RC[8]
            "and    w8, w8, {b:w}",              // (c ^ d) & b
            "eor    w8, w8, {d:w}",              // F(b,c,d)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #25",              // rotate 32-7=25
            "add    {a:w}, {b:w}, w10",          // b + rotated -> new a
            "lsr    {k2}, {k2}, #32",            // prepare RC[9] for next round

            // F9: d, a, b, c, cache9, RC[9], 12 - improved constant handling
            "add    w10, {data9:w}, {k2:w}",     // cache9 + RC[9] - early
            "eor    w8, {b:w}, {c:w}",           // b ^ c
            "add    w10, {d:w}, w10",            // d + cache9 + RC[9]
            "and    w8, w8, {a:w}",              // (b ^ c) & a (using updated a)
            "eor    w8, w8, {c:w}",              // F(a,b,c)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #20",              // rotate 32-12=20
            "add    {d:w}, {a:w}, w10",          // a + rotated -> new d

            // F10: c, d, a, b, cache10, RC[10], 17 - improved register usage
            "add    w10, {data10:w}, {k3:w}",    // cache10 + RC[10] (lower 32 bits) - early
            "eor    w8, {a:w}, {b:w}",           // a ^ b
            "add    w10, {c:w}, w10",            // c + cache10 + RC[10]
            "and    w8, w8, {d:w}",              // (a ^ b) & d
            "eor    w8, w8, {b:w}",              // F(d,a,b)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #15",              // rotate 32-17=15
            "add    {c:w}, {d:w}, w10",          // d + rotated -> new c
            "lsr    {k3}, {k3}, #32",            // prepare RC[11] for next round

            // F11: b, c, d, a, cache11, RC[11], 22 - optimized dependencies
            "add    w10, {data11:w}, {k3:w}",    // cache11 + RC[11] - early
            "eor    w8, {d:w}, {a:w}",           // d ^ a
            "add    w10, {b:w}, w10",            // b + cache11 + RC[11]
            "and    w8, w8, {c:w}",              // (d ^ a) & c
            "eor    w8, w8, {a:w}",              // F(c,d,a)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #10",              // rotate 32-22=10
            "add    {b:w}, {c:w}, w10",          // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data8 = in(reg) cache8,
            data9 = in(reg) cache9,
            data10 = in(reg) cache10,
            data11 = in(reg) cache11,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }
    // F rounds 12-15: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load F round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #48]", // Load RC[12,13] and RC[14,15] pairs
            // F12: a, b, c, d, cache12, RC[12], 7 - optimized scheduling
            "add    w10, {data12:w}, {k2:w}",    // cache12 + RC[12] (lower 32 bits) - early
            "eor    w8, {c:w}, {d:w}",           // c ^ d
            "add    w10, {a:w}, w10",            // a + cache12 + RC[12]
            "and    w8, w8, {b:w}",              // (c ^ d) & b
            "eor    w8, w8, {d:w}",              // F(b,c,d)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #25",              // rotate 32-7=25
            "add    {a:w}, {b:w}, w10",          // b + rotated -> new a
            "lsr    {k2}, {k2}, #32",            // prepare RC[13] for next round

            // F13: d, a, b, c, cache13, RC[13], 12 - improved constant handling
            "add    w10, {data13:w}, {k2:w}",    // cache13 + RC[13] - early
            "eor    w8, {b:w}, {c:w}",           // b ^ c
            "add    w10, {d:w}, w10",            // d + cache13 + RC[13]
            "and    w8, w8, {a:w}",              // (b ^ c) & a (using updated a)
            "eor    w8, w8, {c:w}",              // F(a,b,c)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #20",              // rotate 32-12=20
            "add    {d:w}, {a:w}, w10",          // a + rotated -> new d

            // F14: c, d, a, b, cache14, RC[14], 17 - improved register usage
            "add    w10, {data14:w}, {k3:w}",    // cache14 + RC[14] (lower 32 bits) - early
            "eor    w8, {a:w}, {b:w}",           // a ^ b
            "add    w10, {c:w}, w10",            // c + cache14 + RC[14]
            "and    w8, w8, {d:w}",              // (a ^ b) & d
            "eor    w8, w8, {b:w}",              // F(d,a,b)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #15",              // rotate 32-17=15
            "add    {c:w}, {d:w}, w10",          // d + rotated -> new c
            "lsr    {k3}, {k3}, #32",            // prepare RC[15] for next round

            // F15: b, c, d, a, cache15, RC[15], 22 - optimized dependencies
            "add    w10, {data15:w}, {k3:w}",    // cache15 + RC[15] - early
            "eor    w8, {d:w}, {a:w}",           // d ^ a
            "add    w10, {b:w}, w10",            // b + cache15 + RC[15]
            "and    w8, w8, {c:w}",              // (d ^ a) & c
            "eor    w8, w8, {a:w}",              // F(c,d,a)
            "add    w10, w10, w8",               // complete addition
            "ror    w10, w10, #10",              // rotate 32-22=10
            "add    {b:w}, {c:w}, w10",          // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data12 = in(reg) cache12,
            data13 = in(reg) cache13,
            data14 = in(reg) cache14,
            data15 = in(reg) cache15,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }

    // G rounds 16-19: optimized individual rounds with proper constant loading
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #64]", // Load RC[16,17] and RC[18,19] pairs
            // G0: a, b, c, d, cache1, RC[16], 5 - optimized scheduling
            "add    w10, {data1:w}, {k2:w}",    // cache1 + RC[16] (lower 32 bits) - early
            "bic    w8, {c:w}, {d:w}",          // c & ~d
            "add    w10, {a:w}, w10",           // a + cache1 + RC[16]
            "and    w9, {d:w}, {b:w}",          // d & b
            "add    w10, w10, w8",              // a + cache1 + RC[16] + (c & ~d)
            "add    w8, w10, w9",               // ADD shortcut: + (d & b)
            "ror    w8, w8, #27",               // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",          // b + rotated -> new a

            // G1: d, a, b, c, cache6, RC[17], 9 - improved constant handling
            "lsr    {k2}, {k2}, #32",           // get RC[17] from upper 32 bits - early
            "bic    w8, {b:w}, {c:w}",          // b & ~c
            "add    w10, {data6:w}, {k2:w}",    // cache6 + RC[17]
            "and    w9, {c:w}, {a:w}",          // c & a (using updated a)
            "add    w10, {d:w}, w10",           // d + cache6 + RC[17]
            "add    w10, w10, w8",              // d + cache6 + RC[17] + (b & ~c)
            "add    w8, w10, w9",               // ADD shortcut: + (c & a)
            "ror    w8, w8, #23",               // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",          // a + rotated -> new d

            // G2: c, d, a, b, cache11, RC[18], 14 - improved register usage
            "add    w10, {data11:w}, {k3:w}",   // cache11 + RC[18] (lower 32 bits) - early
            "bic    w8, {a:w}, {b:w}",          // a & ~b
            "add    w10, {c:w}, w10",           // c + cache11 + RC[18]
            "and    w9, {b:w}, {d:w}",          // b & d
            "add    w10, w10, w8",              // c + cache11 + RC[18] + (a & ~b)
            "add    w8, w10, w9",               // ADD shortcut: + (b & d)
            "ror    w8, w8, #18",               // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",          // d + rotated -> new c

            // G3: b, c, d, a, data[0], RC[19], 20 - optimized dependencies
            "lsr    {k3}, {k3}, #32",           // get RC[19] from upper 32 bits - early
            "add    w10, {data0:w}, {k3:w}",    // data[0] + RC[19]
            "bic    w8, {d:w}, {a:w}",          // d & ~a
            "and    w9, {a:w}, {c:w}",          // a & c
            "add    w10, {b:w}, w10",           // b + data[0] + RC[19]
            "add    w10, w10, w8",              // b + data[0] + RC[19] + (d & ~a)
            "add    w8, w10, w9",               // ADD shortcut: + (a & c)
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

    // G rounds 20-23: optimized assembly block to match G16-19 performance
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #80]", // Load RC[20,21] and RC[22,23] pairs
            // G4: a, b, c, d, cache5, RC[20], 5 - optimized scheduling
            "add    w10, {data5:w}, {k2:w}",     // cache5 + RC[20] (lower 32 bits) - early
            "bic    w8, {c:w}, {d:w}",           // c & ~d
            "add    w10, {a:w}, w10",            // a + cache5 + RC[20]
            "and    w9, {d:w}, {b:w}",           // d & b
            "add    w10, w10, w8",               // a + cache5 + RC[20] + (c & ~d)
            "add    w8, w10, w9",                // ADD shortcut: + (d & b)
            "ror    w8, w8, #27",                // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // G5: d, a, b, c, cache10, RC[21], 9 - improved constant handling
            "lsr    {k2}, {k2}, #32",            // get RC[21] from upper 32 bits - early
            "bic    w8, {b:w}, {c:w}",           // b & ~c
            "add    w10, {data10:w}, {k2:w}",    // cache10 + RC[21]
            "and    w9, {c:w}, {a:w}",           // c & a (using updated a)
            "add    w10, {d:w}, w10",            // d + cache10 + RC[21]
            "add    w10, w10, w8",               // d + cache10 + RC[21] + (b & ~c)
            "add    w8, w10, w9",                // ADD shortcut: + (c & a)
            "ror    w8, w8, #23",                // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // G6: c, d, a, b, cache15, RC[22], 14 - improved register usage
            "add    w10, {data15:w}, {k3:w}",    // cache15 + RC[22] (lower 32 bits) - early
            "bic    w8, {a:w}, {b:w}",           // a & ~b
            "add    w10, {c:w}, w10",            // c + cache15 + RC[22]
            "and    w9, {b:w}, {d:w}",           // b & d
            "add    w10, w10, w8",               // c + cache15 + RC[22] + (a & ~b)
            "add    w8, w10, w9",                // ADD shortcut: + (b & d)
            "ror    w8, w8, #18",                // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // G7: b, c, d, a, cache4, RC[23], 20 - optimized dependencies
            "lsr    {k3}, {k3}, #32",            // get RC[23] from upper 32 bits - early
            "add    w10, {data4:w}, {k3:w}",     // cache4 + RC[23]
            "bic    w8, {d:w}, {a:w}",           // d & ~a
            "and    w9, {a:w}, {c:w}",           // a & c
            "add    w10, {b:w}, w10",            // b + cache4 + RC[23]
            "add    w10, w10, w8",               // b + cache4 + RC[23] + (d & ~a)
            "add    w8, w10, w9",                // ADD shortcut: + (a & c)
            "ror    w8, w8, #12",                // rotate by 32-20=12
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data5 = in(reg) cache5,
            data10 = in(reg) cache10,
            data15 = in(reg) cache15,
            data4 = in(reg) cache4,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w9") _,
            out("w10") _,
        );
    }

    // G rounds 24-27: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #96]", // Load RC[24,25] and RC[26,27] pairs
            // G8: a, b, c, d, cache9, RC[24], 5 - optimized scheduling
            "add    w10, {data9:w}, {k2:w}",     // cache9 + RC[24] (lower 32 bits) - early
            "bic    w8, {c:w}, {d:w}",           // c & ~d
            "add    w10, {a:w}, w10",            // a + cache9 + RC[24]
            "and    w9, {d:w}, {b:w}",           // d & b
            "add    w10, w10, w8",               // a + cache9 + RC[24] + (c & ~d)
            "add    w8, w10, w9",                // ADD shortcut: + (d & b)
            "ror    w8, w8, #27",                // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a
            "lsr    {k2}, {k2}, #32",            // prepare RC[25] for next round

            // G9: d, a, b, c, cache14, RC[25], 9 - improved constant handling
            "add    w10, {data14:w}, {k2:w}",    // cache14 + RC[25] - early
            "bic    w8, {b:w}, {c:w}",           // b & ~c
            "add    w10, {d:w}, w10",            // d + cache14 + RC[25]
            "and    w9, {c:w}, {a:w}",           // c & a (using updated a)
            "add    w10, w10, w8",               // d + cache14 + RC[25] + (b & ~c)
            "add    w8, w10, w9",                // ADD shortcut: + (c & a)
            "ror    w8, w8, #23",                // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // G10: c, d, a, b, cache3, RC[26], 14 - improved register usage
            "add    w10, {data3:w}, {k3:w}",     // cache3 + RC[26] (lower 32 bits) - early
            "bic    w8, {a:w}, {b:w}",           // a & ~b
            "add    w10, {c:w}, w10",            // c + cache3 + RC[26]
            "and    w9, {b:w}, {d:w}",           // b & d
            "add    w10, w10, w8",               // c + cache3 + RC[26] + (a & ~b)
            "add    w8, w10, w9",                // ADD shortcut: + (b & d)
            "ror    w8, w8, #18",                // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c
            "lsr    {k3}, {k3}, #32",            // prepare RC[27] for next round

            // G11: b, c, d, a, cache8, RC[27], 20 - optimized dependencies
            "add    w10, {data8:w}, {k3:w}",     // cache8 + RC[27] - early
            "bic    w8, {d:w}, {a:w}",           // d & ~a
            "add    w10, {b:w}, w10",            // b + cache8 + RC[27]
            "and    w9, {a:w}, {c:w}",           // a & c
            "add    w10, w10, w8",               // b + cache8 + RC[27] + (d & ~a)
            "add    w8, w10, w9",                // ADD shortcut: + (a & c)
            "ror    w8, w8, #12",                // rotate by 32-20=12
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data9 = in(reg) cache9,
            data14 = in(reg) cache14,
            data3 = in(reg) cache3,
            data8 = in(reg) cache8,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w9") _,
            out("w10") _,
        );
    }
    // G rounds 28-31: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #112]", // Load RC[28,29] and RC[30,31] pairs
            // G12: a, b, c, d, cache13, RC[28], 5 - optimized scheduling
            "add    w10, {data13:w}, {k2:w}",    // cache13 + RC[28] (lower 32 bits) - early
            "bic    w8, {c:w}, {d:w}",           // c & ~d
            "add    w10, {a:w}, w10",            // a + cache13 + RC[28]
            "and    w9, {d:w}, {b:w}",           // d & b
            "add    w10, w10, w8",               // a + cache13 + RC[28] + (c & ~d)
            "add    w8, w10, w9",                // ADD shortcut: + (d & b)
            "ror    w8, w8, #27",                // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a
            "lsr    {k2}, {k2}, #32",            // prepare RC[29] for next round

            // G13: d, a, b, c, cache2, RC[29], 9 - improved constant handling
            "add    w10, {data2:w}, {k2:w}",     // cache2 + RC[29] - early
            "bic    w8, {b:w}, {c:w}",           // b & ~c
            "add    w10, {d:w}, w10",            // d + cache2 + RC[29]
            "and    w9, {c:w}, {a:w}",           // c & a (using updated a)
            "add    w10, w10, w8",               // d + cache2 + RC[29] + (b & ~c)
            "add    w8, w10, w9",                // ADD shortcut: + (c & a)
            "ror    w8, w8, #23",                // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // G14: c, d, a, b, cache7, RC[30], 14 - improved register usage
            "add    w10, {data7:w}, {k3:w}",     // cache7 + RC[30] (lower 32 bits) - early
            "bic    w8, {a:w}, {b:w}",           // a & ~b
            "add    w10, {c:w}, w10",            // c + cache7 + RC[30]
            "and    w9, {b:w}, {d:w}",           // b & d
            "add    w10, w10, w8",               // c + cache7 + RC[30] + (a & ~b)
            "add    w8, w10, w9",                // ADD shortcut: + (b & d)
            "ror    w8, w8, #18",                // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c
            "lsr    {k3}, {k3}, #32",            // prepare RC[31] for next round

            // G15: b, c, d, a, cache12, RC[31], 20 - optimized dependencies
            "add    w10, {data12:w}, {k3:w}",    // cache12 + RC[31] - early
            "bic    w8, {d:w}, {a:w}",           // d & ~a
            "add    w10, {b:w}, w10",            // b + cache12 + RC[31]
            "and    w9, {a:w}, {c:w}",           // a & c
            "add    w10, w10, w8",               // b + cache12 + RC[31] + (d & ~a)
            "add    w8, w10, w9",                // ADD shortcut: + (a & c)
            "ror    w8, w8, #12",                // rotate by 32-20=12
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data13 = in(reg) cache13,
            data2 = in(reg) cache2,
            data7 = in(reg) cache7,
            data12 = in(reg) cache12,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w9") _,
            out("w10") _,
        );
    }

    // round 3 - H function with re-use optimization
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

    // H rounds 32-35: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load H round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #128]", // Load RC[32,33] and RC[34,35] pairs
            // H0: a, b, c, d, cache5, RC[32], 4 - optimized H function (b ^ c ^ d)
            "add    w10, {data5:w}, {k2:w}",     // cache5 + RC[32] (lower 32 bits) - early
            "eor    w8, {c:w}, {d:w}",           // c ^ d (first part of H function)
            "add    w10, {a:w}, w10",            // a + cache5 + RC[32]
            "eor    w8, w8, {b:w}",              // H(b,c,d) = b ^ c ^ d
            "add    w8, w10, w8",                // a + cache5 + RC[32] + H(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[33] for next round
            "ror    w8, w8, #28",                // rotate by 32-4=28
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // H1: d, a, b, c, cache8, RC[33], 11 - improved constant handling
            "add    w10, {data8:w}, {k2:w}",     // cache8 + RC[33] - early
            "eor    w8, {b:w}, {c:w}",           // b ^ c (with updated values)
            "add    w10, {d:w}, w10",            // d + cache8 + RC[33]
            "eor    w8, w8, {a:w}",              // H(a,b,c) = a ^ b ^ c (using updated a)
            "add    w8, w10, w8",                // d + cache8 + RC[33] + H(a,b,c)
            "ror    w8, w8, #21",                // rotate by 32-11=21
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // H2: c, d, a, b, cache11, RC[34], 16 - improved register usage
            "add    w10, {data11:w}, {k3:w}",    // cache11 + RC[34] (lower 32 bits) - early
            "eor    w8, {a:w}, {b:w}",           // a ^ b (with updated a)
            "add    w10, {c:w}, w10",            // c + cache11 + RC[34]
            "eor    w8, w8, {d:w}",              // H(d,a,b) = d ^ a ^ b (using updated d)
            "add    w8, w10, w8",                // c + cache11 + RC[34] + H(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[35] for next round
            "ror    w8, w8, #16",                // rotate by 32-16=16
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // H3: b, c, d, a, cache14, RC[35], 23 - optimized dependencies
            "add    w10, {data14:w}, {k3:w}",    // cache14 + RC[35] - early
            "eor    w8, {d:w}, {a:w}",           // d ^ a (with updated d)
            "add    w10, {b:w}, w10",            // b + cache14 + RC[35]
            "eor    w8, w8, {c:w}",              // H(c,d,a) = c ^ d ^ a (using updated c)
            "add    w8, w10, w8",                // b + cache14 + RC[35] + H(c,d,a)
            "ror    w8, w8, #9",                 // rotate by 32-23=9
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data5 = in(reg) cache5,
            data8 = in(reg) cache8,
            data11 = in(reg) cache11,
            data14 = in(reg) cache14,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }
    // H rounds 36-39: optimized assembly block to match previous performance
    unsafe {
        core::arch::asm!(
            // Load H round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #144]", // Load RC[36,37] and RC[38,39] pairs
            // H4: a, b, c, d, cache1, RC[36], 4 - optimized H function
            "add    w10, {data1:w}, {k2:w}",     // cache1 + RC[36] (lower 32 bits) - early
            "eor    w8, {c:w}, {d:w}",           // c ^ d (first part of H function)
            "add    w10, {a:w}, w10",            // a + cache1 + RC[36]
            "eor    w8, w8, {b:w}",              // H(b,c,d) = b ^ c ^ d
            "add    w8, w10, w8",                // a + cache1 + RC[36] + H(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[37] for next round
            "ror    w8, w8, #28",                // rotate by 32-4=28
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // H5: d, a, b, c, cache4, RC[37], 11 - improved constant handling
            "add    w10, {data4:w}, {k2:w}",     // cache4 + RC[37] - early
            "eor    w8, {b:w}, {c:w}",           // b ^ c (with updated values)
            "add    w10, {d:w}, w10",            // d + cache4 + RC[37]
            "eor    w8, w8, {a:w}",              // H(a,b,c) = a ^ b ^ c (using updated a)
            "add    w8, w10, w8",                // d + cache4 + RC[37] + H(a,b,c)
            "ror    w8, w8, #21",                // rotate by 32-11=21
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // H6: c, d, a, b, cache7, RC[38], 16 - improved register usage
            "add    w10, {data7:w}, {k3:w}",     // cache7 + RC[38] (lower 32 bits) - early
            "eor    w8, {a:w}, {b:w}",           // a ^ b (with updated a)
            "add    w10, {c:w}, w10",            // c + cache7 + RC[38]
            "eor    w8, w8, {d:w}",              // H(d,a,b) = d ^ a ^ b (using updated d)
            "add    w8, w10, w8",                // c + cache7 + RC[38] + H(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[39] for next round
            "ror    w8, w8, #16",                // rotate by 32-16=16
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // H7: b, c, d, a, cache10, RC[39], 23 - optimized dependencies
            "add    w10, {data10:w}, {k3:w}",    // cache10 + RC[39] - early
            "eor    w8, {d:w}, {a:w}",           // d ^ a (with updated d)
            "add    w10, {b:w}, w10",            // b + cache10 + RC[39]
            "eor    w8, w8, {c:w}",              // H(c,d,a) = c ^ d ^ a (using updated c)
            "add    w8, w10, w8",                // b + cache10 + RC[39] + H(c,d,a)
            "ror    w8, w8, #9",                 // rotate by 32-23=9
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data1 = in(reg) cache1,
            data4 = in(reg) cache4,
            data7 = in(reg) cache7,
            data10 = in(reg) cache10,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }
    // H rounds 40-43: optimized assembly block for consistent performance
    unsafe {
        core::arch::asm!(
            // Load H round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #160]", // Load RC[40,41] and RC[42,43] pairs
            // H8: a, b, c, d, cache13, RC[40], 4 - optimized H function
            "add    w10, {data13:w}, {k2:w}",    // cache13 + RC[40] (lower 32 bits) - early
            "eor    w8, {c:w}, {d:w}",           // c ^ d (first part of H function)
            "add    w10, {a:w}, w10",            // a + cache13 + RC[40]
            "eor    w8, w8, {b:w}",              // H(b,c,d) = b ^ c ^ d
            "add    w8, w10, w8",                // a + cache13 + RC[40] + H(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[41] for next round
            "ror    w8, w8, #28",                // rotate by 32-4=28
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // H9: d, a, b, c, cache0, RC[41], 11 - improved constant handling
            "add    w10, {data0:w}, {k2:w}",     // cache0 + RC[41] - early
            "eor    w8, {b:w}, {c:w}",           // b ^ c (with updated values)
            "add    w10, {d:w}, w10",            // d + cache0 + RC[41]
            "eor    w8, w8, {a:w}",              // H(a,b,c) = a ^ b ^ c (using updated a)
            "add    w8, w10, w8",                // d + cache0 + RC[41] + H(a,b,c)
            "ror    w8, w8, #21",                // rotate by 32-11=21
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // H10: c, d, a, b, cache3, RC[42], 16 - improved register usage
            "add    w10, {data3:w}, {k3:w}",     // cache3 + RC[42] (lower 32 bits) - early
            "eor    w8, {a:w}, {b:w}",           // a ^ b (with updated a)
            "add    w10, {c:w}, w10",            // c + cache3 + RC[42]
            "eor    w8, w8, {d:w}",              // H(d,a,b) = d ^ a ^ b (using updated d)
            "add    w8, w10, w8",                // c + cache3 + RC[42] + H(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[43] for next round
            "ror    w8, w8, #16",                // rotate by 32-16=16
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // H11: b, c, d, a, cache6, RC[43], 23 - optimized dependencies
            "add    w10, {data6:w}, {k3:w}",     // cache6 + RC[43] - early
            "eor    w8, {d:w}, {a:w}",           // d ^ a (with updated d)
            "add    w10, {b:w}, w10",            // b + cache6 + RC[43]
            "eor    w8, w8, {c:w}",              // H(c,d,a) = c ^ d ^ a (using updated c)
            "add    w8, w10, w8",                // b + cache6 + RC[43] + H(c,d,a)
            "ror    w8, w8, #9",                 // rotate by 32-23=9
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data13 = in(reg) cache13,
            data0 = in(reg) cache0,
            data3 = in(reg) cache3,
            data6 = in(reg) cache6,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }
    // Last 4 H rounds use regular asm_op_h! not reuse
    // H44: Inline optimized version
    unsafe {
        core::arch::asm!(
            "eor    w8, {c:w}, {d:w}",          // c ^ d first (independent)
            "add    w9, {m:w}, {rc:w}",         // m + rc in parallel
            "eor    w8, w8, {b:w}",             // (c ^ d) ^ b = b ^ c ^ d
            "add    w9, {a:w}, w9",             // a + m + rc
            "add    w8, w9, w8",                // add h_result
            "ror    w8, w8, #28",               // rotate 32-4=28
            "add    {a:w}, {b:w}, w8",          // b + rotated_result
            a = inout(reg) a,
            b = in(reg) b,
            c = in(reg) c,
            d = in(reg) d,
            m = in(reg) cache9,
            rc = in(reg) RC[44],
            out("w8") _,
            out("w9") _,
        );
    }
    // H round 45: D += H(A,B,C) + cache12 + RC[45]; D = rotl(D, 11) + A - optimized
    unsafe {
        core::arch::asm!(
            "eor    w8, {b:w}, {c:w}",          // b ^ c first (independent)
            "add    w9, {cache12:w}, {rc45:w}", // cache12 + RC[45] (parallel)
            "eor    w8, w8, {a:w}",             // (b ^ c) ^ a = a ^ b ^ c
            "add    w9, {d:w}, w9",             // d + cache12 + RC[45]
            "add    w8, w9, w8",                // add h_result
            "ror    w8, w8, #21",               // rotate 32-11=21
            "add    {d:w}, {a:w}, w8",          // a + rotated_result
            a = in(reg) a,
            b = in(reg) b,
            c = in(reg) c,
            d = inout(reg) d,
            cache12 = in(reg) cache12,
            rc45 = in(reg) RC[45],
            out("w8") _,
            out("w9") _,
        );
    }
    // H round 46: C += H(D,A,B) + cache15 + RC[46]; C = rotl(C, 16) + D - optimized
    unsafe {
        core::arch::asm!(
            "eor    w8, {a:w}, {b:w}",          // a ^ b first (independent)
            "add    w9, {cache15:w}, {rc46:w}", // cache15 + RC[46] (parallel)
            "eor    w8, w8, {d:w}",             // (a ^ b) ^ d = d ^ a ^ b
            "add    w9, {c:w}, w9",             // c + cache15 + RC[46]
            "add    w8, w9, w8",                // add h_result
            "ror    w8, w8, #16",               // rotate 32-16=16
            "add    {c:w}, {d:w}, w8",          // d + rotated_result
            a = in(reg) a,
            b = in(reg) b,
            c = inout(reg) c,
            d = in(reg) d,
            cache15 = in(reg) cache15,
            rc46 = in(reg) RC[46],
            out("w8") _,
            out("w9") _,
        );
    }
    // H round 47: B += H(C,D,A) + cache2 + RC[47]; B = rotl(B, 23) + C - optimized
    unsafe {
        core::arch::asm!(
            "eor    w8, {d:w}, {a:w}",          // d ^ a first (independent)
            "add    w9, {cache2:w}, {rc47:w}",  // cache2 + RC[47] (parallel)
            "eor    w8, w8, {c:w}",             // (d ^ a) ^ c = c ^ d ^ a
            "add    w9, {b:w}, w9",             // b + cache2 + RC[47]
            "add    w8, w9, w8",                // add h_result
            "ror    w8, w8, #9",                // rotate 32-23=9
            "add    {b:w}, {c:w}, w8",          // c + rotated_result
            a = in(reg) a,
            b = inout(reg) b,
            c = in(reg) c,
            d = in(reg) d,
            cache2 = in(reg) cache2,
            rc47 = in(reg) RC[47],
            out("w8") _,
            out("w9") _,
        );
    }

    // I rounds 48-51: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load I round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #192]", // Load RC[48,49] and RC[50,51] pairs
            // I0: a, b, c, d, cache0, RC[48], 6 - optimized I function (~d | b) ^ c
            "add    w10, {data0:w}, {k2:w}",     // cache0 + RC[48] (lower 32 bits) - early
            "orn    w8, {b:w}, {d:w}",           // b | ~d (first part of I function)
            "add    w10, {a:w}, w10",            // a + cache0 + RC[48]
            "eor    w8, w8, {c:w}",              // I(b,c,d) = (b | ~d) ^ c
            "add    w8, w10, w8",                // a + cache0 + RC[48] + I(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[49] for next round
            "ror    w8, w8, #26",                // rotate by 32-6=26
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // I1: d, a, b, c, cache7, RC[49], 10 - improved constant handling
            "add    w10, {data7:w}, {k2:w}",     // cache7 + RC[49] - early
            "orn    w8, {a:w}, {c:w}",           // a | ~c (with updated a)
            "add    w10, {d:w}, w10",            // d + cache7 + RC[49]
            "eor    w8, w8, {b:w}",              // I(a,b,c) = (a | ~c) ^ b
            "add    w8, w10, w8",                // d + cache7 + RC[49] + I(a,b,c)
            "ror    w8, w8, #22",                // rotate by 32-10=22
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // I2: c, d, a, b, cache14, RC[50], 15 - improved register usage
            "add    w10, {data14:w}, {k3:w}",    // cache14 + RC[50] (lower 32 bits) - early
            "orn    w8, {d:w}, {b:w}",           // d | ~b (with updated d)
            "add    w10, {c:w}, w10",            // c + cache14 + RC[50]
            "eor    w8, w8, {a:w}",              // I(d,a,b) = (d | ~b) ^ a
            "add    w8, w10, w8",                // c + cache14 + RC[50] + I(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[51] for next round
            "ror    w8, w8, #17",                // rotate by 32-15=17
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // I3: b, c, d, a, cache5, RC[51], 21 - optimized dependencies
            "add    w10, {data5:w}, {k3:w}",     // cache5 + RC[51] - early
            "orn    w8, {c:w}, {a:w}",           // c | ~a (with updated c)
            "add    w10, {b:w}, w10",            // b + cache5 + RC[51]
            "eor    w8, w8, {d:w}",              // I(c,d,a) = (c | ~a) ^ d
            "add    w8, w10, w8",                // b + cache5 + RC[51] + I(c,d,a)
            "ror    w8, w8, #11",                // rotate by 32-21=11
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data0 = in(reg) cache0,
            data7 = in(reg) cache7,
            data14 = in(reg) cache14,
            data5 = in(reg) cache5,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }
    // I rounds 52-55: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load I round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #208]", // Load RC[52,53] and RC[54,55] pairs
            // I4: a, b, c, d, cache12, RC[52], 6 - optimized I function
            "add    w10, {data12:w}, {k2:w}",    // cache12 + RC[52] (lower 32 bits) - early
            "orn    w8, {b:w}, {d:w}",           // b | ~d (first part of I function)
            "add    w10, {a:w}, w10",            // a + cache12 + RC[52]
            "eor    w8, w8, {c:w}",              // I(b,c,d) = (b | ~d) ^ c
            "add    w8, w10, w8",                // a + cache12 + RC[52] + I(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[53] for next round
            "ror    w8, w8, #26",                // rotate by 32-6=26
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // I5: d, a, b, c, cache3, RC[53], 10 - improved constant handling
            "add    w10, {data3:w}, {k2:w}",     // cache3 + RC[53] - early
            "orn    w8, {a:w}, {c:w}",           // a | ~c (with updated a)
            "add    w10, {d:w}, w10",            // d + cache3 + RC[53]
            "eor    w8, w8, {b:w}",              // I(a,b,c) = (a | ~c) ^ b
            "add    w8, w10, w8",                // d + cache3 + RC[53] + I(a,b,c)
            "ror    w8, w8, #22",                // rotate by 32-10=22
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // I6: c, d, a, b, cache10, RC[54], 15 - improved register usage
            "add    w10, {data10:w}, {k3:w}",    // cache10 + RC[54] (lower 32 bits) - early
            "orn    w8, {d:w}, {b:w}",           // d | ~b (with updated d)
            "add    w10, {c:w}, w10",            // c + cache10 + RC[54]
            "eor    w8, w8, {a:w}",              // I(d,a,b) = (d | ~b) ^ a
            "add    w8, w10, w8",                // c + cache10 + RC[54] + I(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[55] for next round
            "ror    w8, w8, #17",                // rotate by 32-15=17
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // I7: b, c, d, a, cache1, RC[55], 21 - optimized dependencies
            "add    w10, {data1:w}, {k3:w}",     // cache1 + RC[55] - early
            "orn    w8, {c:w}, {a:w}",           // c | ~a (with updated c)
            "add    w10, {b:w}, w10",            // b + cache1 + RC[55]
            "eor    w8, w8, {d:w}",              // I(c,d,a) = (c | ~a) ^ d
            "add    w8, w10, w8",                // b + cache1 + RC[55] + I(c,d,a)
            "ror    w8, w8, #11",                // rotate by 32-21=11
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data12 = in(reg) cache12,
            data3 = in(reg) cache3,
            data10 = in(reg) cache10,
            data1 = in(reg) cache1,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }

    // I rounds 56-59: optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load I round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #224]", // Load RC[56,57] and RC[58,59] pairs
            // I8: a, b, c, d, cache8, RC[56], 6 - optimized I function
            "add    w10, {data8:w}, {k2:w}",     // cache8 + RC[56] (lower 32 bits) - early
            "orn    w8, {b:w}, {d:w}",           // b | ~d (first part of I function)
            "add    w10, {a:w}, w10",            // a + cache8 + RC[56]
            "eor    w8, w8, {c:w}",              // I(b,c,d) = (b | ~d) ^ c
            "add    w8, w10, w8",                // a + cache8 + RC[56] + I(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[57] for next round
            "ror    w8, w8, #26",                // rotate by 32-6=26
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // I9: d, a, b, c, cache15, RC[57], 10 - improved constant handling
            "add    w10, {data15:w}, {k2:w}",    // cache15 + RC[57] - early
            "orn    w8, {a:w}, {c:w}",           // a | ~c (with updated a)
            "add    w10, {d:w}, w10",            // d + cache15 + RC[57]
            "eor    w8, w8, {b:w}",              // I(a,b,c) = (a | ~c) ^ b
            "add    w8, w10, w8",                // d + cache15 + RC[57] + I(a,b,c)
            "ror    w8, w8, #22",                // rotate by 32-10=22
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // I10: c, d, a, b, cache6, RC[58], 15 - improved register usage
            "add    w10, {data6:w}, {k3:w}",     // cache6 + RC[58] (lower 32 bits) - early
            "orn    w8, {d:w}, {b:w}",           // d | ~b (with updated d)
            "add    w10, {c:w}, w10",            // c + cache6 + RC[58]
            "eor    w8, w8, {a:w}",              // I(d,a,b) = (d | ~b) ^ a
            "add    w8, w10, w8",                // c + cache6 + RC[58] + I(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[59] for next round
            "ror    w8, w8, #17",                // rotate by 32-15=17
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // I11: b, c, d, a, cache13, RC[59], 21 - optimized dependencies
            "add    w10, {data13:w}, {k3:w}",    // cache13 + RC[59] - early
            "orn    w8, {c:w}, {a:w}",           // c | ~a (with updated c)
            "add    w10, {b:w}, w10",            // b + cache13 + RC[59]
            "eor    w8, w8, {d:w}",              // I(c,d,a) = (c | ~a) ^ d
            "add    w8, w10, w8",                // b + cache13 + RC[59] + I(c,d,a)
            "ror    w8, w8, #11",                // rotate by 32-21=11
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data8 = in(reg) cache8,
            data15 = in(reg) cache15,
            data6 = in(reg) cache6,
            data13 = in(reg) cache13,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }

    // I rounds 60-63: final optimized assembly block for maximum performance
    unsafe {
        core::arch::asm!(
            // Load I round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #240]", // Load RC[60,61] and RC[62,63] pairs
            // I12: a, b, c, d, cache4, RC[60], 6 - optimized I function
            "add    w10, {data4:w}, {k2:w}",     // cache4 + RC[60] (lower 32 bits) - early
            "orn    w8, {b:w}, {d:w}",           // b | ~d (first part of I function)
            "add    w10, {a:w}, w10",            // a + cache4 + RC[60]
            "eor    w8, w8, {c:w}",              // I(b,c,d) = (b | ~d) ^ c
            "add    w8, w10, w8",                // a + cache4 + RC[60] + I(b,c,d)
            "lsr    {k2}, {k2}, #32",            // prepare RC[61] for next round
            "ror    w8, w8, #26",                // rotate by 32-6=26
            "add    {a:w}, {b:w}, w8",           // b + rotated -> new a

            // I13: d, a, b, c, cache11, RC[61], 10 - improved constant handling
            "add    w10, {data11:w}, {k2:w}",    // cache11 + RC[61] - early
            "orn    w8, {a:w}, {c:w}",           // a | ~c (with updated a)
            "add    w10, {d:w}, w10",            // d + cache11 + RC[61]
            "eor    w8, w8, {b:w}",              // I(a,b,c) = (a | ~c) ^ b
            "add    w8, w10, w8",                // d + cache11 + RC[61] + I(a,b,c)
            "ror    w8, w8, #22",                // rotate by 32-10=22
            "add    {d:w}, {a:w}, w8",           // a + rotated -> new d

            // I14: c, d, a, b, cache2, RC[62], 15 - improved register usage
            "add    w10, {data2:w}, {k3:w}",     // cache2 + RC[62] (lower 32 bits) - early
            "orn    w8, {d:w}, {b:w}",           // d | ~b (with updated d)
            "add    w10, {c:w}, w10",            // c + cache2 + RC[62]
            "eor    w8, w8, {a:w}",              // I(d,a,b) = (d | ~b) ^ a
            "add    w8, w10, w8",                // c + cache2 + RC[62] + I(d,a,b)
            "lsr    {k3}, {k3}, #32",            // prepare RC[63] for next round
            "ror    w8, w8, #17",                // rotate by 32-15=17
            "add    {c:w}, {d:w}, w8",           // d + rotated -> new c

            // I15: b, c, d, a, cache9, RC[63], 21 - final optimized dependencies
            "add    w10, {data9:w}, {k3:w}",     // cache9 + RC[63] - early
            "orn    w8, {c:w}, {a:w}",           // c | ~a (with updated c)
            "add    w10, {b:w}, w10",            // b + cache9 + RC[63]
            "eor    w8, w8, {d:w}",              // I(c,d,a) = (c | ~a) ^ d
            "add    w8, w10, w8",                // b + cache9 + RC[63] + I(c,d,a)
            "ror    w8, w8, #11",                // rotate by 32-21=11
            "add    {b:w}, {c:w}, w8",           // c + rotated -> new b

            a = inout(reg) a,
            b = inout(reg) b,
            c = inout(reg) c,
            d = inout(reg) d,
            data4 = in(reg) cache4,
            data11 = in(reg) cache11,
            data2 = in(reg) cache2,
            data9 = in(reg) cache9,
            k2 = out(reg) _,
            k3 = out(reg) _,
            const_ptr = in(reg) MD5_CONSTANTS_PACKED.as_ptr(),
            out("w8") _,
            out("w10") _,
        );
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[inline]
pub(crate) fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}
