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

// Alternative F function implementation with eor+and+eor pattern
macro_rules! asm_op_f_alt {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Alternative F function: F(b,c,d) = (c^d)&b ^ d
                "add    {a:w}, {a:w}, {m:w}",       // a += m
                "eor    w8, {c:w}, {d:w}",          // c ^ d
                "add    {a:w}, {a:w}, {rc:w}",      // a += rc
                "and    w8, w8, {b:w}",             // (c ^ d) & b
                "eor    w8, w8, {d:w}",             // ((c ^ d) & b) ^ d = F(b,c,d)
                "add    {a:w}, {a:w}, w8",          // a += F(b,c,d)
                "ror    {a:w}, {a:w}, #{ror}",      // rotate
                "add    {a:w}, {a:w}, {b:w}",       // a += b
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

// Alternative G function implementation with bic+and pattern
macro_rules! asm_op_g_alt {
    ($a:ident, $b:ident, $c:ident, $d:ident, $m:expr, $rc:expr, $s:expr) => {
        unsafe {
            core::arch::asm!(
                // Alternative G function: G(b,c,d) = (c & !d) + (b & d)
                "bic    w8, {c:w}, {d:w}",      // c & !d
                "add    {a:w}, {a:w}, {rc:w}",  // a += rc
                "and    w9, {b:w}, {d:w}",      // b & d
                "add    {a:w}, {a:w}, {m:w}",   // a += m
                "add    w8, w8, w9",            // (c & !d) + (b & d) = G(b,c,d)
                "add    {a:w}, {a:w}, w8",      // a += G(b,c,d)
                "ror    {a:w}, {a:w}, #{ror}",  // rotate
                "add    {a:w}, {a:w}, {b:w}",   // a += b
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
                "add    w9, {cache0:w}, w10",            // cache0 + RC[k0] (lower 32 bits)
                "eor    {tmp:w}, {tmp:w}, {b:w}",        // reuse: tmp (c^d) ^ b = b^c^d
                "lsr    x10, x10, #32",                  // shift for next constant
                "add    w9, {a:w}, w9",                  // a + cache0 + RC[k0]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {d:w}",        // prepare for next: (b^c^d) ^ d = b^c
                "ror    w8, w8, #28",                    // rotate 32-4=28
                "add    {a:w}, {b:w}, w8",               // b + rotated_result

                // H round 1: D += H(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 11) + A
                "add    w9, {cache1:w}, w10",            // cache1 + RC[k+1]
                "eor    {tmp:w}, {tmp:w}, {a:w}",        // reuse: tmp (b^c) ^ a = a^b^c
                "add    w9, {d:w}, w9",                  // d + cache1 + RC[k+1]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {c:w}",        // prepare for next: (a^b^c) ^ c = a^b
                "ror    w8, w8, #21",                    // rotate 32-11=21
                "add    {d:w}, {a:w}, w8",               // a + rotated_result

                // H round 2: C += H(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 16) + D
                "add    w9, {cache2:w}, w11",            // cache2 + RC[k+2] (lower k1)
                "eor    {tmp:w}, {tmp:w}, {d:w}",        // reuse: tmp (a^b) ^ d = d^a^b
                "lsr    x11, x11, #32",                  // shift for next constant
                "add    w9, {c:w}, w9",                  // c + cache2 + RC[k+2]
                "add    w8, w9, {tmp:w}",                // add h_result
                "eor    {tmp:w}, {tmp:w}, {b:w}",        // prepare for next: (d^a^b) ^ b = d^a
                "ror    w8, w8, #16",                    // rotate 32-16=16
                "add    {c:w}, {d:w}, w8",               // d + rotated_result

                // H round 3: B += H(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 23) + C
                "add    w9, {cache3:w}, w11",            // cache3 + RC[k+3]
                "eor    {tmp:w}, {tmp:w}, {c:w}",        // reuse: tmp (d^a) ^ c = c^d^a
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
                "add    {a:w}, {a:w}, {cache0:w}",       // a += cache0
                "eor    w12, {c:w}, {d:w}",              // c ^ d (alt F function)
                "add    {a:w}, {a:w}, w10",              // a += RC[k0] (lower 32 bits)
                "and    w12, w12, {b:w}",                // (c ^ d) & b
                "lsr    x10, x10, #32",                  // shift for next constant
                "eor    w12, w12, {d:w}",                // F(b,c,d)
                "add    {a:w}, {a:w}, w12",              // a += F(b,c,d)
                "ror    {a:w}, {a:w}, #25",              // rotate by 25 (optimized)
                "add    {a:w}, {a:w}, {b:w}",            // a += b

                // F round 1: D += F(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 12) + A
                "eor    w12, {b:w}, {c:w}",              // b ^ c (independent calc first)
                "add    {d:w}, {d:w}, {cache1:w}",       // d += cache1 (parallel)
                "and    w12, w12, {a:w}",                // (b ^ c) & a
                "add    {d:w}, {d:w}, w10",              // d += RC[k+1]
                "eor    w12, w12, {c:w}",                // F(a,b,c)
                "add    {d:w}, {d:w}, w12",              // d += F(a,b,c)
                "ror    {d:w}, {d:w}, #20",              // rotate by 20 (optimized)
                "add    {d:w}, {d:w}, {a:w}",            // d += a

                // F round 2: C += F(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 17) + D
                "eor    w12, {a:w}, {b:w}",              // a ^ b (independent calc first)
                "add    {c:w}, {c:w}, {cache2:w}",       // c += cache2 (parallel)
                "and    w12, w12, {d:w}",                // (a ^ b) & d
                "add    {c:w}, {c:w}, w11",              // c += RC[k+2] (lower k1)
                "lsr    x11, x11, #32",                  // shift for next constant (early)
                "eor    w12, w12, {b:w}",                // F(d,a,b)
                "add    {c:w}, {c:w}, w12",              // c += F(d,a,b)
                "ror    {c:w}, {c:w}, #15",              // rotate by 15 (optimized)
                "add    {c:w}, {c:w}, {d:w}",            // c += d

                // F round 3: B += F(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 22) + C
                "eor    w12, {d:w}, {a:w}",              // d ^ a (independent calc first)
                "add    {b:w}, {b:w}, {cache3:w}",       // b += cache3 (parallel)
                "and    w12, w12, {c:w}",                // (d ^ a) & c
                "add    {b:w}, {b:w}, w11",              // b += RC[k+3]
                "eor    w12, w12, {a:w}",                // F(c,d,a)
                "add    {b:w}, {b:w}, w12",              // b += F(c,d,a)
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

// Integrated RG4 with alternative G function and ldp constant loading
macro_rules! rg4_integrated {
    ($a:ident, $b:ident, $c:ident, $d:ident, $cache0:ident, $cache1:ident, $cache2:ident, $cache3:ident, $rc0:expr, $rc1:expr, $rc2:expr, $rc3:expr, $const_ptr:expr, $offset:expr) => {
        unsafe {
            core::arch::asm!(
                // Load RC constant pairs with ldp for better throughput
                "ldp    x10, x11, [{const_ptr}, #{k_offset}]",    // Load RC pair

                // G round 0: A += G(B,C,D) + cache0 + RC[k]; A = rotl(A, 5) + B
                "bic    w12, {c:w}, {d:w}",              // c & ~d (independent G calc first)
                "add    {a:w}, {a:w}, {cache0:w}",       // a += cache0 (parallel)
                "and    w8, {d:w}, {b:w}",               // d & b (parallel)
                "add    {a:w}, {a:w}, w10",              // a += RC[k0] (lower 32 bits)
                "lsr    x10, x10, #32",                  // shift for next constant (early)
                "orr    w12, w12, w8",                   // G(b,c,d)
                "add    {a:w}, {a:w}, w12",              // a += G(b,c,d)
                "ror    {a:w}, {a:w}, #27",              // rotate 32-5=27
                "add    {a:w}, {a:w}, {b:w}",            // a += b

                // G round 1: D += G(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 9) + A
                "bic    w12, {b:w}, {c:w}",              // b & ~c (independent G calc first)
                "add    {d:w}, {d:w}, {cache1:w}",       // d += cache1 (parallel)
                "and    w8, {c:w}, {a:w}",               // c & a (parallel)
                "add    {d:w}, {d:w}, w10",              // d += RC[k+1]
                "orr    w12, w12, w8",                   // G(a,b,c)
                "add    {d:w}, {d:w}, w12",              // d += G(a,b,c)
                "ror    {d:w}, {d:w}, #23",              // rotate 32-9=23
                "add    {d:w}, {d:w}, {a:w}",            // d += a

                // G round 2: C += G(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 14) + D
                "add    {c:w}, {c:w}, {cache2:w}",       // c += cache2
                "bic    w12, {a:w}, {b:w}",              // a & ~b
                "add    {c:w}, {c:w}, w11",              // c += RC[k+2] (lower k1)
                "and    w8, {b:w}, {d:w}",               // b & d
                "lsr    x11, x11, #32",                  // shift for next constant
                "orr    w12, w12, w8",                   // G(d,a,b)
                "add    {c:w}, {c:w}, w12",              // c += G(d,a,b)
                "ror    {c:w}, {c:w}, #18",              // rotate 32-14=18
                "add    {c:w}, {c:w}, {d:w}",            // c += d

                // G round 3: B += G(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 20) + C
                "add    {b:w}, {b:w}, {cache3:w}",       // b += cache3
                "bic    w12, {d:w}, {a:w}",              // d & ~a
                "add    {b:w}, {b:w}, w11",              // b += RC[k+3]
                "and    w8, {a:w}, {c:w}",               // a & c
                "orr    w12, w12, w8",                   // G(c,d,a)
                "add    {b:w}, {b:w}, w12",              // b += G(c,d,a)
                "ror    {b:w}, {b:w}, #12",              // rotate 32-20=12
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
                out("w8") _,
                out("w12") _,
            );
        }
    };
}

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
                "eor    w12, w12, {c:w}",                // (b | ~d) ^ c = I(b,c,d)
                "add    {a:w}, {a:w}, w10",              // a += RC[k0] (lower 32 bits)
                "lsr    x10, x10, #32",                  // shift for next constant (early)
                "add    {a:w}, {a:w}, w12",              // a += I(b,c,d)
                "ror    {a:w}, {a:w}, #26",              // rotate 32-6=26
                "add    {a:w}, {a:w}, {b:w}",            // a += b

                // I round 1: D += I(A,B,C) + cache1 + RC[k+1]; D = rotl(D, 10) + A
                "orn    w12, {a:w}, {c:w}",              // a | ~c (independent I function calc)
                "add    {d:w}, {d:w}, {cache1:w}",       // d += cache1 (parallel)
                "eor    w12, w12, {b:w}",                // (a | ~c) ^ b = I(a,b,c)
                "add    {d:w}, {d:w}, w10",              // d += RC[k+1]
                "add    {d:w}, {d:w}, w12",              // d += I(a,b,c)
                "ror    {d:w}, {d:w}, #22",              // rotate 32-10=22
                "add    {d:w}, {d:w}, {a:w}",            // d += a

                // I round 2: C += I(D,A,B) + cache2 + RC[k+2]; C = rotl(C, 15) + D
                "orn    w12, {d:w}, {b:w}",              // d | ~b (independent I function calc)
                "add    {c:w}, {c:w}, {cache2:w}",       // c += cache2 (parallel)
                "eor    w12, w12, {a:w}",                // (d | ~b) ^ a = I(d,a,b)
                "add    {c:w}, {c:w}, w11",              // c += RC[k+2] (lower k1)
                "lsr    x11, x11, #32",                  // shift for next constant (early)
                "add    {c:w}, {c:w}, w12",              // c += I(d,a,b)
                "ror    {c:w}, {c:w}, #17",              // rotate 32-15=17
                "add    {c:w}, {c:w}, {d:w}",            // c += d

                // I round 3: B += I(C,D,A) + cache3 + RC[k+3]; B = rotl(B, 21) + C
                "orn    w12, {c:w}, {a:w}",              // c | ~a (independent I function calc)
                "add    {b:w}, {b:w}, {cache3:w}",       // b += cache3 (parallel)
                "eor    w12, w12, {d:w}",                // (c | ~a) ^ d = I(c,d,a)
                "add    {b:w}, {b:w}, w11",              // b += RC[k+3]
                "add    {b:w}, {b:w}, w12",              // b += I(c,d,a)
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

    // Additional optimizations: better instruction scheduling and reduced dependencies

    // round 1 - first 4 operations with ldp constants optimization
    unsafe {
        core::arch::asm!(
            // Load first two constant pairs with ldp
            "ldp    {k0}, {k1}, [{const_ptr}]",  // Load RC[0,1] and RC[2,3] pairs
            // F0: a, b, c, d, data[0], RC[0], 7 - optimized scheduling
            "add    w10, {data0:w}, {k0:w}",    // data[0] + RC[0] (lower 32 bits) - start early
            "and    w8, {b:w}, {c:w}",          // b & c
            "bic    w9, {d:w}, {b:w}",          // d & !b
            "add    w9, {a:w}, w9",             // a + (d & !b)
            "add    w10, w9, w10",              // a + (d & !b) + data[0] + RC[0]
            "add    w8, w10, w8",               // add (b & c)
            "ror    w8, w8, #25",               // rotate by 32-7=25
            "add    {a:w}, {b:w}, w8",          // b + rotated -> new a

            // F1: d, a, b, c, cache1, RC[1], 12 - optimized scheduling
            "lsr    {k0}, {k0}, #32",           // get RC[1] from upper 32 bits - start early
            "and    w8, {a:w}, {b:w}",          // a & b (using updated a)
            "add    w10, {data1:w}, {k0:w}",    // cache1 + RC[1]
            "bic    w9, {c:w}, {a:w}",          // c & !a
            "add    w9, {d:w}, w9",             // d + (c & !a)
            "add    w10, w9, w10",              // d + (c & !a) + cache1 + RC[1]
            "add    w8, w10, w8",               // add (a & b)
            "ror    w8, w8, #20",               // rotate by 32-12=20
            "add    {d:w}, {a:w}, w8",          // a + rotated -> new d

            // F2: c, d, a, b, cache2, RC[2], 17 - optimized scheduling
            "add    w10, {data2:w}, {k1:w}",    // cache2 + RC[2] (lower 32 bits) - start early
            "and    w8, {d:w}, {a:w}",          // d & a
            "bic    w9, {b:w}, {d:w}",          // b & !d
            "add    w9, {c:w}, w9",             // c + (b & !d)
            "add    w10, w9, w10",              // c + (b & !d) + cache2 + RC[2]
            "add    w8, w10, w8",               // add (d & a)
            "ror    w8, w8, #15",               // rotate by 32-17=15
            "add    {c:w}, {d:w}, w8",          // d + rotated -> new c

            // F3: b, c, d, a, cache3, RC[3], 22 - optimized scheduling
            "lsr    {k1}, {k1}, #32",           // get RC[3] from upper 32 bits - start early
            "and    w8, {c:w}, {d:w}",          // c & d
            "add    w10, {data3:w}, {k1:w}",    // cache3 + RC[3]
            "bic    w9, {a:w}, {c:w}",          // a & !c
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

    // F rounds 4-12: test alternative F function with eor+and+eor pattern
    asm_op_f_alt!(a, b, c, d, cache4, RC[4], 7);
    asm_op_f_alt!(d, a, b, c, cache5, RC[5], 12);
    asm_op_f_alt!(c, d, a, b, cache6, RC[6], 17);
    asm_op_f_alt!(b, c, d, a, cache7, RC[7], 22);
    rf4_integrated!(
        a,
        b,
        c,
        d,
        cache8,
        cache9,
        cache10,
        cache11,
        RC[8],
        RC[9],
        RC[10],
        RC[11],
        MD5_CONSTANTS_PACKED.as_ptr(),
        32
    );
    rf4_integrated!(
        a,
        b,
        c,
        d,
        cache12,
        cache13,
        cache14,
        cache15,
        RC[12],
        RC[13],
        RC[14],
        RC[15],
        MD5_CONSTANTS_PACKED.as_ptr(),
        48
    );

    // round 2 - first 4 G operations with ldp constants optimization
    unsafe {
        core::arch::asm!(
            // Load G round constant pairs with ldp
            "ldp    {k2}, {k3}, [{const_ptr}, #64]", // Load RC[16,17] and RC[18,19] pairs
            // G0: a, b, c, d, cache1, RC[16], 5 - optimized scheduling
            "add    w10, {data1:w}, {k2:w}",    // cache1 + RC[16] (lower 32 bits) - early
            "and    w8, {b:w}, {d:w}",          // b & d
            "add    w10, {a:w}, w10",           // a + cache1 + RC[16]
            "bic    w9, {c:w}, {d:w}",          // c & !d
            "add    w10, w10, w9",              // a + cache1 + RC[16] + (c & !d)
            "add    w8, w10, w8",               // ADD shortcut: + (b & d)
            "ror    w8, w8, #27",               // rotate by 32-5=27
            "add    {a:w}, {b:w}, w8",          // b + rotated -> new a

            // G1: d, a, b, c, cache6, RC[17], 9 - improved constant handling
            "lsr    {k2}, {k2}, #32",           // get RC[17] from upper 32 bits - early
            "and    w8, {a:w}, {c:w}",          // a & c (using updated a)
            "add    w10, {data6:w}, {k2:w}",    // cache6 + RC[17]
            "bic    w9, {b:w}, {c:w}",          // b & !c
            "add    w10, {d:w}, w10",           // d + cache6 + RC[17]
            "add    w10, w10, w9",              // d + cache6 + RC[17] + (b & !c)
            "add    w8, w10, w8",               // ADD shortcut: + (a & c)
            "ror    w8, w8, #23",               // rotate by 32-9=23
            "add    {d:w}, {a:w}, w8",          // a + rotated -> new d

            // G2: c, d, a, b, cache11, RC[18], 14 - improved register usage
            "add    w10, {data11:w}, {k3:w}",   // cache11 + RC[18] (lower 32 bits) - early
            "and    w8, {d:w}, {b:w}",          // d & b
            "add    w10, {c:w}, w10",           // c + cache11 + RC[18]
            "bic    w9, {a:w}, {b:w}",          // a & !b
            "add    w10, w10, w9",              // c + cache11 + RC[18] + (a & !b)
            "add    w8, w10, w8",               // ADD shortcut: + (d & b)
            "ror    w8, w8, #18",               // rotate by 32-14=18
            "add    {c:w}, {d:w}, w8",          // d + rotated -> new c

            // G3: b, c, d, a, data[0], RC[19], 20 - optimized dependencies  
            "lsr    {k3}, {k3}, #32",           // get RC[19] from upper 32 bits - early
            "add    w10, {data0:w}, {k3:w}",    // data[0] + RC[19]
            "and    w8, {c:w}, {a:w}",          // c & a
            "bic    w9, {d:w}, {a:w}",          // d & !a
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

    // G rounds 20-32: test alternative G function with bic+and pattern
    asm_op_g_alt!(a, b, c, d, cache5, RC[20], 5);
    asm_op_g_alt!(d, a, b, c, cache10, RC[21], 9);
    asm_op_g_alt!(c, d, a, b, cache15, RC[22], 14);
    asm_op_g_alt!(b, c, d, a, cache4, RC[23], 20);
    rg4_integrated!(
        a,
        b,
        c,
        d,
        cache9,
        cache14,
        cache3,
        cache8,
        RC[24],
        RC[25],
        RC[26],
        RC[27],
        MD5_CONSTANTS_PACKED.as_ptr(),
        96
    );
    rg4_integrated!(
        a,
        b,
        c,
        d,
        cache13,
        cache2,
        cache7,
        cache12,
        RC[28],
        RC[29],
        RC[30],
        RC[31],
        MD5_CONSTANTS_PACKED.as_ptr(),
        112
    );

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

    // H rounds 32-48: use RH4 macro for better instruction scheduling
    // Note: H rounds use reuse optimization for rounds 32-43, regular H for rounds 44-47
    rh4_integrated!(
        a,
        b,
        c,
        d,
        cache5,
        cache8,
        cache11,
        cache14,
        RC[32],
        RC[33],
        RC[34],
        RC[35],
        MD5_CONSTANTS_PACKED.as_ptr(),
        128,
        tmp_h
    );
    rh4_integrated!(
        a,
        b,
        c,
        d,
        cache1,
        cache4,
        cache7,
        cache10,
        RC[36],
        RC[37],
        RC[38],
        RC[39],
        MD5_CONSTANTS_PACKED.as_ptr(),
        144,
        tmp_h
    );
    #[allow(unused_assignments)] // Last RH4 reuse writes tmp_h but it's not used after
    {
        rh4_integrated!(
            a,
            b,
            c,
            d,
            cache13,
            cache0,
            cache3,
            cache6,
            RC[40],
            RC[41],
            RC[42],
            RC[43],
            MD5_CONSTANTS_PACKED.as_ptr(),
            160,
            tmp_h
        );
    }
    // Last 4 H rounds use regular asm_op_h! not reuse
    asm_op_h!(a, b, c, d, cache9, RC[44], 4);
    asm_op_h!(d, a, b, c, cache12, RC[45], 11);
    asm_op_h!(c, d, a, b, cache15, RC[46], 16);
    asm_op_h!(b, c, d, a, cache2, RC[47], 23);

    // I rounds 48-64: use RI4 macro for better instruction scheduling
    ri4_integrated!(
        a,
        b,
        c,
        d,
        cache0,
        cache7,
        cache14,
        cache5,
        RC[48],
        RC[49],
        RC[50],
        RC[51],
        MD5_CONSTANTS_PACKED.as_ptr(),
        192
    );
    ri4_integrated!(
        a,
        b,
        c,
        d,
        cache12,
        cache3,
        cache10,
        cache1,
        RC[52],
        RC[53],
        RC[54],
        RC[55],
        MD5_CONSTANTS_PACKED.as_ptr(),
        208
    );
    ri4_integrated!(
        a,
        b,
        c,
        d,
        cache8,
        cache15,
        cache6,
        cache13,
        RC[56],
        RC[57],
        RC[58],
        RC[59],
        MD5_CONSTANTS_PACKED.as_ptr(),
        224
    );
    ri4_integrated!(
        a,
        b,
        c,
        d,
        cache4,
        cache11,
        cache2,
        cache9,
        RC[60],
        RC[61],
        RC[62],
        RC[63],
        MD5_CONSTANTS_PACKED.as_ptr(),
        240
    );

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
