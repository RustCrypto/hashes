//! MD5 assembly code for `x86_64` and `x86`. Adapted from Project Nayuki.
/*
 * MD5 hash in x86-64 assembly
 *
 * Copyright (c) 2016 Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */
use core::arch::asm;

use asm_block::asm_block;

/// MD5 operators
macro_rules! asm_md5_op {
    (F, $a: tt, $b: tt, $c: tt, $d: tt, $k: tt, $s: literal, $t: literal, $tmp1: tt, $tmp2: tt) => {
        concat!(
            asm_block! {
                mov $tmp1, $c;
                add $a, $k;
                xor $tmp1, $d;
                and $tmp1, $b;
                xor $tmp1, $d;
            },
            asm_md5_op!(END, $a, $b, $s, $t, $tmp1)
        )
    };
    (G, $a: tt, $b: tt, $c: tt, $d: tt, $k: tt, $s: literal, $t: literal, $tmp1: tt, $tmp2: tt) => {
        concat!(
            asm_block! {
                mov $tmp1, $d;
                mov $tmp2, $d;
                add $a, $k;
                not $tmp1;
                and $tmp2, $b;
                and $tmp1, $c;
                or $tmp1, $tmp2;
            },
            asm_md5_op!(END, $a, $b, $s, $t, $tmp1)
        )
    };
    (H, $a: tt, $b: tt, $c: tt, $d: tt, $k: tt, $s: literal, $t: literal, $tmp1: tt, $tmp2: tt) => {
        concat!(
            asm_block! {
                mov $tmp1, $c;
                add $a, $k;
                xor $tmp1, $d;
                xor $tmp1, $b;
            },
            asm_md5_op!(END, $a, $b, $s, $t, $tmp1)
        )
    };
    (I, $a: tt, $b: tt, $c: tt, $d: tt, $k: tt, $s: literal, $t: literal, $tmp1: tt, $tmp2: tt) => {
        concat!(
            asm_block! {
                mov $tmp1, $d;
                not $tmp1;
                add $a, $k;
                or $tmp1, $b;
                xor $tmp1, $c;
            },
            asm_md5_op!(END, $a, $b, $s, $t, $tmp1)
        )
    };
    (END, $a: tt, $b: tt, $s: literal, $t: literal, $tmp: tt) => {
        asm_block! {
            lea $a, [$a + $tmp + $t];
            rol $a, $s;
            add $a, $b;
        }
    };
}

/// MD5 rounds, adding back the original value of states is omitted here
#[rustfmt::skip]
macro_rules! asm_md5 {
    (
        // states
        $a: tt, $b: tt, $c: tt, $d: tt,
        // inputs
        $x0: tt, $x1: tt, $x2: tt, $x3: tt,
        $x4: tt, $x5: tt, $x6: tt, $x7: tt,
        $x8: tt, $x9: tt, $xa: tt, $xb: tt,
        $xc: tt, $xd: tt, $xe: tt, $xf: tt,
        // clobbers
        $t1: tt, $t2: tt
     ) => {
        concat!(
            // round 1
            asm_md5_op!(F, $a, $b, $c, $d, $x0,  7, 0xd76aa478, $t1, $t2),
            asm_md5_op!(F, $d, $a, $b, $c, $x1, 12, 0xe8c7b756, $t1, $t2),
            asm_md5_op!(F, $c, $d, $a, $b, $x2, 17, 0x242070db, $t1, $t2),
            asm_md5_op!(F, $b, $c, $d, $a, $x3, 22, 0xc1bdceee, $t1, $t2),
   
            asm_md5_op!(F, $a, $b, $c, $d, $x4,  7, 0xf57c0faf, $t1, $t2),
            asm_md5_op!(F, $d, $a, $b, $c, $x5, 12, 0x4787c62a, $t1, $t2),
            asm_md5_op!(F, $c, $d, $a, $b, $x6, 17, 0xa8304613, $t1, $t2),
            asm_md5_op!(F, $b, $c, $d, $a, $x7, 22, 0xfd469501, $t1, $t2),
 
            asm_md5_op!(F, $a, $b, $c, $d, $x8,  7, 0x698098d8, $t1, $t2),
            asm_md5_op!(F, $d, $a, $b, $c, $x9, 12, 0x8b44f7af, $t1, $t2),
            asm_md5_op!(F, $c, $d, $a, $b, $xa, 17, 0xffff5bb1, $t1, $t2),
            asm_md5_op!(F, $b, $c, $d, $a, $xb, 22, 0x895cd7be, $t1, $t2),
 
            asm_md5_op!(F, $a, $b, $c, $d, $xc,  7, 0x6b901122, $t1, $t2),
            asm_md5_op!(F, $d, $a, $b, $c, $xd, 12, 0xfd987193, $t1, $t2),
            asm_md5_op!(F, $c, $d, $a, $b, $xe, 17, 0xa679438e, $t1, $t2),
            asm_md5_op!(F, $b, $c, $d, $a, $xf, 22, 0x49b40821, $t1, $t2),

            // round 2
            asm_md5_op!(G, $a, $b, $c, $d, $x1,  5, 0xf61e2562, $t1, $t2),
            asm_md5_op!(G, $d, $a, $b, $c, $x6,  9, 0xc040b340, $t1, $t2),
            asm_md5_op!(G, $c, $d, $a, $b, $xb, 14, 0x265e5a51, $t1, $t2),
            asm_md5_op!(G, $b, $c, $d, $a, $x0, 20, 0xe9b6c7aa, $t1, $t2),

            asm_md5_op!(G, $a, $b, $c, $d, $x5,  5, 0xd62f105d, $t1, $t2),
            asm_md5_op!(G, $d, $a, $b, $c, $xa,  9, 0x02441453, $t1, $t2),
            asm_md5_op!(G, $c, $d, $a, $b, $xf, 14, 0xd8a1e681, $t1, $t2),
            asm_md5_op!(G, $b, $c, $d, $a, $x4, 20, 0xe7d3fbc8, $t1, $t2),

            asm_md5_op!(G, $a, $b, $c, $d, $x9,  5, 0x21e1cde6, $t1, $t2),
            asm_md5_op!(G, $d, $a, $b, $c, $xe,  9, 0xc33707d6, $t1, $t2),
            asm_md5_op!(G, $c, $d, $a, $b, $x3, 14, 0xf4d50d87, $t1, $t2),
            asm_md5_op!(G, $b, $c, $d, $a, $x8, 20, 0x455a14ed, $t1, $t2),

            asm_md5_op!(G, $a, $b, $c, $d, $xd,  5, 0xa9e3e905, $t1, $t2),
            asm_md5_op!(G, $d, $a, $b, $c, $x2,  9, 0xfcefa3f8, $t1, $t2),
            asm_md5_op!(G, $c, $d, $a, $b, $x7, 14, 0x676f02d9, $t1, $t2),
            asm_md5_op!(G, $b, $c, $d, $a, $xc, 20, 0x8d2a4c8a, $t1, $t2),

            // round 3
            asm_md5_op!(H, $a, $b, $c, $d, $x5,  4, 0xfffa3942, $t1, $t2),
            asm_md5_op!(H, $d, $a, $b, $c, $x8, 11, 0x8771f681, $t1, $t2),
            asm_md5_op!(H, $c, $d, $a, $b, $xb, 16, 0x6d9d6122, $t1, $t2),
            asm_md5_op!(H, $b, $c, $d, $a, $xe, 23, 0xfde5380c, $t1, $t2),

            asm_md5_op!(H, $a, $b, $c, $d, $x1,  4, 0xa4beea44, $t1, $t2),
            asm_md5_op!(H, $d, $a, $b, $c, $x4, 11, 0x4bdecfa9, $t1, $t2),
            asm_md5_op!(H, $c, $d, $a, $b, $x7, 16, 0xf6bb4b60, $t1, $t2),
            asm_md5_op!(H, $b, $c, $d, $a, $xa, 23, 0xbebfbc70, $t1, $t2),

            asm_md5_op!(H, $a, $b, $c, $d, $xd,  4, 0x289b7ec6, $t1, $t2),
            asm_md5_op!(H, $d, $a, $b, $c, $x0, 11, 0xeaa127fa, $t1, $t2),
            asm_md5_op!(H, $c, $d, $a, $b, $x3, 16, 0xd4ef3085, $t1, $t2),
            asm_md5_op!(H, $b, $c, $d, $a, $x6, 23, 0x04881d05, $t1, $t2),

            asm_md5_op!(H, $a, $b, $c, $d, $x9,  4, 0xd9d4d039, $t1, $t2),
            asm_md5_op!(H, $d, $a, $b, $c, $xc, 11, 0xe6db99e5, $t1, $t2),
            asm_md5_op!(H, $c, $d, $a, $b, $xf, 16, 0x1fa27cf8, $t1, $t2),
            asm_md5_op!(H, $b, $c, $d, $a, $x2, 23, 0xc4ac5665, $t1, $t2),

            // round 4
            asm_md5_op!(I, $a, $b, $c, $d, $x0,  6, 0xf4292244, $t1, $t2),
            asm_md5_op!(I, $d, $a, $b, $c, $x7, 10, 0x432aff97, $t1, $t2),
            asm_md5_op!(I, $c, $d, $a, $b, $xe, 15, 0xab9423a7, $t1, $t2),
            asm_md5_op!(I, $b, $c, $d, $a, $x5, 21, 0xfc93a039, $t1, $t2),

            asm_md5_op!(I, $a, $b, $c, $d, $xc,  6, 0x655b59c3, $t1, $t2),
            asm_md5_op!(I, $d, $a, $b, $c, $x3, 10, 0x8f0ccc92, $t1, $t2),
            asm_md5_op!(I, $c, $d, $a, $b, $xa, 15, 0xffeff47d, $t1, $t2),
            asm_md5_op!(I, $b, $c, $d, $a, $x1, 21, 0x85845dd1, $t1, $t2),

            asm_md5_op!(I, $a, $b, $c, $d, $x8,  6, 0x6fa87e4f, $t1, $t2),
            asm_md5_op!(I, $d, $a, $b, $c, $xf, 10, 0xfe2ce6e0, $t1, $t2),
            asm_md5_op!(I, $c, $d, $a, $b, $x6, 15, 0xa3014314, $t1, $t2),
            asm_md5_op!(I, $b, $c, $d, $a, $xd, 21, 0x4e0811a1, $t1, $t2),

            asm_md5_op!(I, $a, $b, $c, $d, $x4,  6, 0xf7537e82, $t1, $t2),
            asm_md5_op!(I, $d, $a, $b, $c, $xb, 10, 0xbd3af235, $t1, $t2),
            asm_md5_op!(I, $c, $d, $a, $b, $x2, 15, 0x2ad7d2bb, $t1, $t2),
            asm_md5_op!(I, $b, $c, $d, $a, $x9, 21, 0xeb86d391, $t1, $t2),
        )
    };
}

/// MD5 compress function. We don't have enough registers to load the whole block,
/// so we need to use memory address to refer to the inputs. But there are enough
/// registers to to house states, block address, and clobbers (12 in total), so we
/// can use automatical register allocation.
#[cfg(target_arch = "x86_64")]
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    // SAFETY: inline-assembly
    unsafe {
        asm!(
            // exit if no block
            "cmp {cnt}, 0",
            "jz 3f",

            "2:",
            // duplicate state vector for this iteration
            "mov {a:e}, {sa:e}",
            "mov {b:e}, {sb:e}",
            "mov {c:e}, {sc:e}",
            "mov {d:e}, {sd:e}",

            asm_md5!(
                // states
                {a:e}, {b:e}, {c:e}, {d:e},
                // inputs
                [{x} +  0], [{x} +  4], [{x} +  8], [{x} + 12],
                [{x} + 16], [{x} + 20], [{x} + 24], [{x} + 28],
                [{x} + 32], [{x} + 36], [{x} + 40], [{x} + 44],
                [{x} + 48], [{x} + 52], [{x} + 56], [{x} + 60],
                // clobbers
                {t1:e}, {t2:e}
            ),

            // update state
            "add {sa:e}, {a:e}",
            "add {sb:e}, {b:e}",
            "add {sc:e}, {c:e}",
            "add {sd:e}, {d:e}",

            // check end of loop?
            "dec {cnt}",
            "jz 3f",

            // advance block pointer
            // 4 * 16 = 64 bytes
            "add {x}, 64",

            "jmp 2b",

            // exit
            "3:",

            // states clobbers
            a = out(reg) _,
            b = out(reg) _,
            c = out(reg) _,
            d = out(reg) _,
            // output states
            sa = inout(reg) state[0],
            sb = inout(reg) state[1],
            sc = inout(reg) state[2],
            sd = inout(reg) state[3],
            // inputs
            x = in(reg) blocks.as_ptr(),
            cnt = in(reg) blocks.len(),
            // clobbers
            t1 = out(reg) _,
            t2 = out(reg) _,
        );
    }
}

/// MD5 compress function. We don't have enough registers to load the whole block,
/// so we need to use memory address to refer to the inputs. Due to possible failure
/// of register allocation on `x86`, we explicitly specify registers to use.
#[cfg(target_arch = "x86")]
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    // SAFETY: inline-assembly
    unsafe {
        asm!(
            // exit if no block
            "cmp ebx, 0",
            "jz 4f",

            // save esi and ebp
            // save state vector address
            // move block count to stack
            "sub esp, 32",
            "mov [esp + 0], esi",
            "mov [esp + 4], ebp",
            // address of `state`
            "mov [esp + 8], eax",
            // block count
            "mov [esp + 12], ebx",

            // we can now use all registers
            // we will move eax into ebp, save states on stack and set eax-edx as states
            "mov ebp, eax",
            "mov eax, [ebp + 0]",
            "mov [esp + 16], eax",
            "mov ebx, [ebp + 4]",
            "mov [esp + 20], ebx",
            "mov ecx, [ebp + 8]",
            "mov [esp + 24], ecx",
            "mov edx, [ebp + 12]",
            "mov [esp + 28], edx",

            "2:",
            asm_md5!(
                // states
                eax, ebx, ecx, edx,
                // inputs
                [edi +  0], [edi +  4], [edi +  8], [edi + 12],
                [edi + 16], [edi + 20], [edi + 24], [edi + 28],
                [edi + 32], [edi + 36], [edi + 40], [edi + 44],
                [edi + 48], [edi + 52], [edi + 56], [edi + 60],
                // clobbers
                esi, ebp
            ),

            // update state
            "add eax, [esp + 16]",
            "add ebx, [esp + 20]",
            "add ecx, [esp + 24]",
            "add edx, [esp + 28]",

            // check end of loop?
            "mov esi, [esp + 12]",
            "dec esi",
            "jz 3f",

            // save current state to stack
            "mov [esp + 16], eax",
            "mov [esp + 20], ebx",
            "mov [esp + 24], ecx",
            "mov [esp + 28], edx",
            "mov [esp + 12], esi",

            // advance block pointer
            // 4 * 16 = 64 bytes
            "add edi, 64",

            "jmp 2b",

            "3:",
            // write to state vector
            "mov ebp, [esp + 8]",
            "mov [ebp + 0], eax",
            "mov [ebp + 4], ebx",
            "mov [ebp + 8], ecx",
            "mov [ebp + 12], edx",

            // restore esi and ebp
            "mov esi, [esp + 0]",
            "mov ebp, [esp + 4]",
            "add esp, 32",

            // exit
            "4:",

            // states
            inout("eax") state.as_mut_ptr() => _,
            // inputs
            inout("edi") blocks.as_ptr() => _,
            inout("ebx") blocks.len() => _,

            // clobbers
            out("ecx") _,
            out("edx") _,
        );
    }
}
