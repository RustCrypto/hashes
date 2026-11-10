// x86_64 assembly backend

use crate::consts::RC as K;

#[allow(unused_assignments)] // t1 is written by the F-round asm block and read by G+H+I
#[allow(clippy::too_many_lines)] // intentionally monolithic for the assembler
#[allow(clippy::many_single_char_names)] // a/b/c/d/m are standard MD5 register names
#[allow(clippy::cast_ptr_alignment)] // read_unaligned semantics via asm memory operands
#[allow(clippy::cast_possible_wrap)] // K constants are bit-patterns; sign is irrelevant
#[inline(always)]
fn compress_block(state: &mut [u32; 4], block: &[u8; 64]) {
    use core::arch::asm;

    let m = block.as_ptr().cast::<u32>();

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let (sa, sb, sc, sd) = (a, b, c, d);

    // Scratch registers shared across both asm blocks.
    let mut t1: u32; // rolling C copy / xor-and scratch
    let mut t2: u32; // G second-term scratch

    // SAFETY: all pointer arithmetic stays within the 64-byte block and the
    // 4-word state array.  Register constraints satisfy Rust inline-asm rules.
    unsafe {
        // ── Block 1: 16 F rounds (NoLEA) ────────────────────────────────────
        //
        // ROUND_F(A, B, C, D, next_input_offset, K, R):
        //   xor  C,       TMP1   ; TMP1 ^= C  (TMP1 was prior C)
        //   add  $K,      A
        //   and  B,       TMP1   ; TMP1 = B & (C^D)
        //   xor  D,       TMP1   ; TMP1 = D ^ (B&(C^D)) = F(B,C,D)
        //   add  [m+off], D      ; pre-load next round's input word into D
        //   add  TMP1,    A
        //   rol  $R,      A
        //   mov  C,       TMP1   ; prep for next round
        //   add  B,       A
        //
        // Preamble: A += input[0],  TMP1 = D  (seeds the rolling C copy as D).
        asm!(
            // preamble
            "add {a:e}, dword ptr [{m} + 0]",
            "mov {t1:e}, {d:e}",
            // F round 1: input[1] pre-loaded into D
            "xor {t1:e}, {c:e}",
            "add {a:e}, {k0}",
            "and {t1:e}, {b:e}",
            "xor {t1:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 4]",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 7",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // F round 2: (d,a,b,c) — input[2]->c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {k1}",
            "and {t1:e}, {a:e}",
            "xor {t1:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 8]",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 12",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // F round 3: (c,d,a,b) — input[3]->b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {k2}",
            "and {t1:e}, {d:e}",
            "xor {t1:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 12]",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 17",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // F round 4: (b,c,d,a) — input[4]->a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {k3}",
            "and {t1:e}, {c:e}",
            "xor {t1:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 16]",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 22",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // F round 5: (a,b,c,d) — input[5]->d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {k4}",
            "and {t1:e}, {b:e}",
            "xor {t1:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 20]",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 7",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // F round 6: (d,a,b,c) — input[6]->c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {k5}",
            "and {t1:e}, {a:e}",
            "xor {t1:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 24]",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 12",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // F round 7: (c,d,a,b) — input[7]->b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {k6}",
            "and {t1:e}, {d:e}",
            "xor {t1:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 28]",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 17",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // F round 8: (b,c,d,a) — input[8]->a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {k7}",
            "and {t1:e}, {c:e}",
            "xor {t1:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 32]",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 22",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // F round 9: (a,b,c,d) — input[9]->d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {k8}",
            "and {t1:e}, {b:e}",
            "xor {t1:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 36]",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 7",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // F round 10: (d,a,b,c) — input[10]->c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {k9}",
            "and {t1:e}, {a:e}",
            "xor {t1:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 40]",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 12",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // F round 11: (c,d,a,b) — input[11]->b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {k10}",
            "and {t1:e}, {d:e}",
            "xor {t1:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 44]",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 17",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // F round 12: (b,c,d,a) — input[12]->a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {k11}",
            "and {t1:e}, {c:e}",
            "xor {t1:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 48]",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 22",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // F round 13: (a,b,c,d) — input[13]->d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {k12}",
            "and {t1:e}, {b:e}",
            "xor {t1:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 52]",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 7",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // F round 14: (d,a,b,c) — input[14]->c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {k13}",
            "and {t1:e}, {a:e}",
            "xor {t1:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 56]",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 12",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // F round 15: (c,d,a,b) — input[15]->b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {k14}",
            "and {t1:e}, {d:e}",
            "xor {t1:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 60]",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 17",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // F round 16: (b,c,d,a) — pre-loads input[1] into a for G1
            "xor {t1:e}, {d:e}",
            "add {b:e}, {k15}",
            "and {t1:e}, {c:e}",
            "xor {t1:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 4]",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 22",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            a   = inout(reg) a,
            b   = inout(reg) b,
            c   = inout(reg) c,
            d   = inout(reg) d,
            t1  = out(reg) t1,
            m   = in(reg) m,
            k0  = const K[0]  as i32,
            k1  = const K[1]  as i32,
            k2  = const K[2]  as i32,
            k3  = const K[3]  as i32,
            k4  = const K[4]  as i32,
            k5  = const K[5]  as i32,
            k6  = const K[6]  as i32,
            k7  = const K[7]  as i32,
            k8  = const K[8]  as i32,
            k9  = const K[9]  as i32,
            k10 = const K[10] as i32,
            k11 = const K[11] as i32,
            k12 = const K[12] as i32,
            k13 = const K[13] as i32,
            k14 = const K[14] as i32,
            k15 = const K[15] as i32,
            options(nostack),
        );

        // ── Block 2: G (NoLEA-GOpt) + H (NoLEA) + I (NoLEA) rounds ─────────
        //
        // ROUND_G(A, B, C, D, next_off, K, R):
        //   not  TMP1         ; TMP1 = ~C  (TMP1 was C)
        //   add  $K,    A
        //   and  TMP1,  C_reg ; (in register rotation, this is actually ~prev_C=~D)
        //   mov  D,     TMP2
        //   add  [off], D     ; pre-load next input into D
        //   add  TMP1,  A     ; A += ~D & C  (GOpt first term)
        //   and  B,     TMP2  ; TMP2 = D & B
        //   add  TMP2,  A     ; A += D & B   (GOpt second term)
        //   rol  $R,    A
        //   mov  C,     TMP1  ; prep for next round
        //   add  B,     A
        //
        // ROUND_H(A, B, C, D, next_off, K, R):
        //   xor  C,     TMP1  ; TMP1 ^= C
        //   add  $K,    A
        //   add  [off], D     ; pre-load
        //   xor  B,     TMP1  ; TMP1 = B^C^D = H(B,C,D)  -- wait, see note
        //   add  TMP1,  A
        //   rol  $R,    A
        //   mov  C,     TMP1
        //   add  B,     A
        //
        //   NOTE on H: TMP1 was C from previous round.  xor TMP1,C makes TMP1=C^C'
        //   where C' is now the next 'C' in the ABCD rotation. After the second xor
        //   with B we get B^C^D = H(B,C,D). The `add [next], D` happens between
        //   the two xors, so the pre-load memory latency is hidden.
        //
        // ROUND_I(A, B, C, D, next_off, K, R):
        //   not  TMP1         ; TMP1 = ~C (was C)
        //   add  $K,    A
        //   add  [off], D     ; pre-load
        //   or   B,     TMP1  ; TMP1 = B | ~C  (= B | ~D in I's role)
        //   xor  C_cur, TMP1  ; TMP1 = C ^ (B | ~D) = I(B,C,D)
        //   add  TMP1,  A
        //   rol  $R,    A
        //   mov  C,     TMP1
        //   add  B,     A
        //
        // G input indices: (1 + 5*i) mod 16
        //   1,6,11,0, 5,10,15,4, 9,14,3,8, 13,2,7,12
        // H input indices: (5 + 3*i) mod 16
        //   5,8,11,14, 1,4,7,10, 13,0,3,6, 9,12,15,2
        // I input indices: (7*i) mod 16
        //   0,7,14,5, 12,3,10,1, 8,15,6,13, 4,11,2,9
        //
        // Pre-load target is the "D" register of each ROUND_X call.
        // Pre-load value is the NEXT round's input index (not the current one).

        asm!(
            // ── G rounds ────────────────────────────────────────────────────
            // G1: (a,b,c,d) cur=input[1] (pre-loaded by F16 into a),
            //     pre-loads G2 input[6] into d (D-pos)
            "not {t1:e}",
            "add {a:e}, {kg0}",
            "and {t1:e}, {c:e}",
            "mov {t2:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 24]",
            "add {a:e}, {t1:e}",
            "and {t2:e}, {b:e}",
            "add {a:e}, {t2:e}",
            "rol {a:e}, 5",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // G2: (d,a,b,c) cur=input[6], pre-loads G3 input[11] into c
            "not {t1:e}",
            "add {d:e}, {kg1}",
            "and {t1:e}, {b:e}",
            "mov {t2:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 44]",
            "add {d:e}, {t1:e}",
            "and {t2:e}, {a:e}",
            "add {d:e}, {t2:e}",
            "rol {d:e}, 9",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // G3: (c,d,a,b) cur=input[11], pre-loads G4 input[0] into b
            "not {t1:e}",
            "add {c:e}, {kg2}",
            "and {t1:e}, {a:e}",
            "mov {t2:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 0]",
            "add {c:e}, {t1:e}",
            "and {t2:e}, {d:e}",
            "add {c:e}, {t2:e}",
            "rol {c:e}, 14",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // G4: (b,c,d,a) cur=input[0], pre-loads G5 input[5] into a
            "not {t1:e}",
            "add {b:e}, {kg3}",
            "and {t1:e}, {d:e}",
            "mov {t2:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 20]",
            "add {b:e}, {t1:e}",
            "and {t2:e}, {c:e}",
            "add {b:e}, {t2:e}",
            "rol {b:e}, 20",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // G5: (a,b,c,d) cur=input[5], pre-loads G6 input[10] into d
            "not {t1:e}",
            "add {a:e}, {kg4}",
            "and {t1:e}, {c:e}",
            "mov {t2:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 40]",
            "add {a:e}, {t1:e}",
            "and {t2:e}, {b:e}",
            "add {a:e}, {t2:e}",
            "rol {a:e}, 5",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // G6: (d,a,b,c) cur=input[10], pre-loads G7 input[15] into c
            "not {t1:e}",
            "add {d:e}, {kg5}",
            "and {t1:e}, {b:e}",
            "mov {t2:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 60]",
            "add {d:e}, {t1:e}",
            "and {t2:e}, {a:e}",
            "add {d:e}, {t2:e}",
            "rol {d:e}, 9",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // G7: (c,d,a,b) cur=input[15], pre-loads G8 input[4] into b
            "not {t1:e}",
            "add {c:e}, {kg6}",
            "and {t1:e}, {a:e}",
            "mov {t2:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 16]",
            "add {c:e}, {t1:e}",
            "and {t2:e}, {d:e}",
            "add {c:e}, {t2:e}",
            "rol {c:e}, 14",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // G8: (b,c,d,a) cur=input[4], pre-loads G9 input[9] into a
            "not {t1:e}",
            "add {b:e}, {kg7}",
            "and {t1:e}, {d:e}",
            "mov {t2:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 36]",
            "add {b:e}, {t1:e}",
            "and {t2:e}, {c:e}",
            "add {b:e}, {t2:e}",
            "rol {b:e}, 20",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // G9: (a,b,c,d) cur=input[9], pre-loads G10 input[14] into d
            "not {t1:e}",
            "add {a:e}, {kg8}",
            "and {t1:e}, {c:e}",
            "mov {t2:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 56]",
            "add {a:e}, {t1:e}",
            "and {t2:e}, {b:e}",
            "add {a:e}, {t2:e}",
            "rol {a:e}, 5",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // G10: (d,a,b,c) cur=input[14], pre-loads G11 input[3] into c
            "not {t1:e}",
            "add {d:e}, {kg9}",
            "and {t1:e}, {b:e}",
            "mov {t2:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 12]",
            "add {d:e}, {t1:e}",
            "and {t2:e}, {a:e}",
            "add {d:e}, {t2:e}",
            "rol {d:e}, 9",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // G11: (c,d,a,b) cur=input[3], pre-loads G12 input[8] into b
            "not {t1:e}",
            "add {c:e}, {kg10}",
            "and {t1:e}, {a:e}",
            "mov {t2:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 32]",
            "add {c:e}, {t1:e}",
            "and {t2:e}, {d:e}",
            "add {c:e}, {t2:e}",
            "rol {c:e}, 14",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // G12: (b,c,d,a) cur=input[8], pre-loads G13 input[13] into a
            "not {t1:e}",
            "add {b:e}, {kg11}",
            "and {t1:e}, {d:e}",
            "mov {t2:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 52]",
            "add {b:e}, {t1:e}",
            "and {t2:e}, {c:e}",
            "add {b:e}, {t2:e}",
            "rol {b:e}, 20",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // G13: (a,b,c,d) cur=input[13], pre-loads G14 input[2] into d
            "not {t1:e}",
            "add {a:e}, {kg12}",
            "and {t1:e}, {c:e}",
            "mov {t2:e}, {d:e}",
            "add {d:e}, dword ptr [{m} + 8]",
            "add {a:e}, {t1:e}",
            "and {t2:e}, {b:e}",
            "add {a:e}, {t2:e}",
            "rol {a:e}, 5",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // G14: (d,a,b,c) cur=input[2], pre-loads G15 input[7] into c
            "not {t1:e}",
            "add {d:e}, {kg13}",
            "and {t1:e}, {b:e}",
            "mov {t2:e}, {c:e}",
            "add {c:e}, dword ptr [{m} + 28]",
            "add {d:e}, {t1:e}",
            "and {t2:e}, {a:e}",
            "add {d:e}, {t2:e}",
            "rol {d:e}, 9",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // G15: (c,d,a,b) cur=input[7], pre-loads G16 input[12] into b
            "not {t1:e}",
            "add {c:e}, {kg14}",
            "and {t1:e}, {a:e}",
            "mov {t2:e}, {b:e}",
            "add {b:e}, dword ptr [{m} + 48]",
            "add {c:e}, {t1:e}",
            "and {t2:e}, {d:e}",
            "add {c:e}, {t2:e}",
            "rol {c:e}, 14",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // G16: (b,c,d,a) cur=input[12], pre-loads H1 input[5] into a
            "not {t1:e}",
            "add {b:e}, {kg15}",
            "and {t1:e}, {d:e}",
            "mov {t2:e}, {a:e}",
            "add {a:e}, dword ptr [{m} + 20]",
            "add {b:e}, {t1:e}",
            "and {t2:e}, {c:e}",
            "add {b:e}, {t2:e}",
            "rol {b:e}, 20",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",

            // ── H rounds ────────────────────────────────────────────────────
            // ROUND_H(A,B,C,D, next_off, K, R):
            //   xor C, TMP1 ; add $K, A ; add [next], D ; xor B, TMP1
            //   add TMP1, A ; rol $R, A ; mov C, TMP1 ; add B, A
            // H input indices: 5,8,11,14, 1,4,7,10, 13,0,3,6, 9,12,15,2
            // H1: (a,b,c,d) cur=input[5] (from G16→a), pre-loads H2 input[8] into d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {kh0}",
            "add {d:e}, dword ptr [{m} + 32]",
            "xor {t1:e}, {b:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 4",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // H2: (d,a,b,c) cur=input[8], pre-loads H3 input[11] into c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {kh1}",
            "add {c:e}, dword ptr [{m} + 44]",
            "xor {t1:e}, {a:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 11",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // H3: (c,d,a,b) cur=input[11], pre-loads H4 input[14] into b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {kh2}",
            "add {b:e}, dword ptr [{m} + 56]",
            "xor {t1:e}, {d:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 16",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // H4: (b,c,d,a) cur=input[14], pre-loads H5 input[1] into a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {kh3}",
            "add {a:e}, dword ptr [{m} + 4]",
            "xor {t1:e}, {c:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 23",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // H5: (a,b,c,d) cur=input[1], pre-loads H6 input[4] into d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {kh4}",
            "add {d:e}, dword ptr [{m} + 16]",
            "xor {t1:e}, {b:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 4",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // H6: (d,a,b,c) cur=input[4], pre-loads H7 input[7] into c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {kh5}",
            "add {c:e}, dword ptr [{m} + 28]",
            "xor {t1:e}, {a:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 11",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // H7: (c,d,a,b) cur=input[7], pre-loads H8 input[10] into b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {kh6}",
            "add {b:e}, dword ptr [{m} + 40]",
            "xor {t1:e}, {d:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 16",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // H8: (b,c,d,a) cur=input[10], pre-loads H9 input[13] into a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {kh7}",
            "add {a:e}, dword ptr [{m} + 52]",
            "xor {t1:e}, {c:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 23",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // H9: (a,b,c,d) cur=input[13], pre-loads H10 input[0] into d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {kh8}",
            "add {d:e}, dword ptr [{m} + 0]",
            "xor {t1:e}, {b:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 4",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // H10: (d,a,b,c) cur=input[0], pre-loads H11 input[3] into c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {kh9}",
            "add {c:e}, dword ptr [{m} + 12]",
            "xor {t1:e}, {a:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 11",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // H11: (c,d,a,b) cur=input[3], pre-loads H12 input[6] into b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {kh10}",
            "add {b:e}, dword ptr [{m} + 24]",
            "xor {t1:e}, {d:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 16",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // H12: (b,c,d,a) cur=input[6], pre-loads H13 input[9] into a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {kh11}",
            "add {a:e}, dword ptr [{m} + 36]",
            "xor {t1:e}, {c:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 23",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // H13: (a,b,c,d) cur=input[9], pre-loads H14 input[12] into d
            "xor {t1:e}, {c:e}",
            "add {a:e}, {kh12}",
            "add {d:e}, dword ptr [{m} + 48]",
            "xor {t1:e}, {b:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 4",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // H14: (d,a,b,c) cur=input[12], pre-loads H15 input[15] into c
            "xor {t1:e}, {b:e}",
            "add {d:e}, {kh13}",
            "add {c:e}, dword ptr [{m} + 60]",
            "xor {t1:e}, {a:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 11",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // H15: (c,d,a,b) cur=input[15], pre-loads H16 input[2] into b
            "xor {t1:e}, {a:e}",
            "add {c:e}, {kh14}",
            "add {b:e}, dword ptr [{m} + 8]",
            "xor {t1:e}, {d:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 16",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // H16: (b,c,d,a) cur=input[2], pre-loads I1 input[0] into a
            "xor {t1:e}, {d:e}",
            "add {b:e}, {kh15}",
            "add {a:e}, dword ptr [{m} + 0]",
            "xor {t1:e}, {c:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 23",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",

            // ── I rounds ────────────────────────────────────────────────────
            // ROUND_I(A,B,C,D, next_off, K, R):
            //   not TMP1 ; add $K, A ; add [next], D ; or B, TMP1
            //   xor C, TMP1 ; add TMP1, A ; rol $R, A ; mov C, TMP1 ; add B, A
            // I input indices: 0,7,14,5, 12,3,10,1, 8,15,6,13, 4,11,2,9
            // I1: (a,b,c,d) cur=input[0] (from H16→a), pre-loads I2 input[7] into d
            "not {t1:e}",
            "add {a:e}, {ki0}",
            "add {d:e}, dword ptr [{m} + 28]",
            "or  {t1:e}, {b:e}",
            "xor {t1:e}, {c:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 6",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // I2: (d,a,b,c) cur=input[7], pre-loads I3 input[14] into c
            "not {t1:e}",
            "add {d:e}, {ki1}",
            "add {c:e}, dword ptr [{m} + 56]",
            "or  {t1:e}, {a:e}",
            "xor {t1:e}, {b:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 10",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // I3: (c,d,a,b) cur=input[14], pre-loads I4 input[5] into b
            "not {t1:e}",
            "add {c:e}, {ki2}",
            "add {b:e}, dword ptr [{m} + 20]",
            "or  {t1:e}, {d:e}",
            "xor {t1:e}, {a:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 15",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // I4: (b,c,d,a) cur=input[5], pre-loads I5 input[12] into a
            "not {t1:e}",
            "add {b:e}, {ki3}",
            "add {a:e}, dword ptr [{m} + 48]",
            "or  {t1:e}, {c:e}",
            "xor {t1:e}, {d:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 21",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // I5: (a,b,c,d) cur=input[12], pre-loads I6 input[3] into d
            "not {t1:e}",
            "add {a:e}, {ki4}",
            "add {d:e}, dword ptr [{m} + 12]",
            "or  {t1:e}, {b:e}",
            "xor {t1:e}, {c:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 6",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // I6: (d,a,b,c) cur=input[3], pre-loads I7 input[10] into c
            "not {t1:e}",
            "add {d:e}, {ki5}",
            "add {c:e}, dword ptr [{m} + 40]",
            "or  {t1:e}, {a:e}",
            "xor {t1:e}, {b:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 10",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // I7: (c,d,a,b) cur=input[10], pre-loads I8 input[1] into b
            "not {t1:e}",
            "add {c:e}, {ki6}",
            "add {b:e}, dword ptr [{m} + 4]",
            "or  {t1:e}, {d:e}",
            "xor {t1:e}, {a:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 15",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // I8: (b,c,d,a) cur=input[1], pre-loads I9 input[8] into a
            "not {t1:e}",
            "add {b:e}, {ki7}",
            "add {a:e}, dword ptr [{m} + 32]",
            "or  {t1:e}, {c:e}",
            "xor {t1:e}, {d:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 21",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // I9: (a,b,c,d) cur=input[8], pre-loads I10 input[15] into d
            "not {t1:e}",
            "add {a:e}, {ki8}",
            "add {d:e}, dword ptr [{m} + 60]",
            "or  {t1:e}, {b:e}",
            "xor {t1:e}, {c:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 6",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // I10: (d,a,b,c) cur=input[15], pre-loads I11 input[6] into c
            "not {t1:e}",
            "add {d:e}, {ki9}",
            "add {c:e}, dword ptr [{m} + 24]",
            "or  {t1:e}, {a:e}",
            "xor {t1:e}, {b:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 10",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // I11: (c,d,a,b) cur=input[6], pre-loads I12 input[13] into b
            "not {t1:e}",
            "add {c:e}, {ki10}",
            "add {b:e}, dword ptr [{m} + 52]",
            "or  {t1:e}, {d:e}",
            "xor {t1:e}, {a:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 15",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // I12: (b,c,d,a) cur=input[13], pre-loads I13 input[4] into a
            "not {t1:e}",
            "add {b:e}, {ki11}",
            "add {a:e}, dword ptr [{m} + 16]",
            "or  {t1:e}, {c:e}",
            "xor {t1:e}, {d:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 21",
            "mov {t1:e}, {d:e}",
            "add {b:e}, {c:e}",
            // I13: (a,b,c,d) cur=input[4], pre-loads I14 input[11] into d
            "not {t1:e}",
            "add {a:e}, {ki12}",
            "add {d:e}, dword ptr [{m} + 44]",
            "or  {t1:e}, {b:e}",
            "xor {t1:e}, {c:e}",
            "add {a:e}, {t1:e}",
            "rol {a:e}, 6",
            "mov {t1:e}, {c:e}",
            "add {a:e}, {b:e}",
            // I14: (d,a,b,c) cur=input[11], pre-loads I15 input[2] into c
            "not {t1:e}",
            "add {d:e}, {ki13}",
            "add {c:e}, dword ptr [{m} + 8]",
            "or  {t1:e}, {a:e}",
            "xor {t1:e}, {b:e}",
            "add {d:e}, {t1:e}",
            "rol {d:e}, 10",
            "mov {t1:e}, {b:e}",
            "add {d:e}, {a:e}",
            // I15: (c,d,a,b) cur=input[2], pre-loads I16 input[9] into b
            "not {t1:e}",
            "add {c:e}, {ki14}",
            "add {b:e}, dword ptr [{m} + 36]",
            "or  {t1:e}, {d:e}",
            "xor {t1:e}, {a:e}",
            "add {c:e}, {t1:e}",
            "rol {c:e}, 15",
            "mov {t1:e}, {a:e}",
            "add {c:e}, {d:e}",
            // I16: (b,c,d,a) cur=input[9] (pre-loaded by I15 into b), last round
            "not {t1:e}",
            "add {b:e}, {ki15}",
            "or  {t1:e}, {c:e}",
            "xor {t1:e}, {d:e}",
            "add {b:e}, {t1:e}",
            "rol {b:e}, 21",
            "add {b:e}, {c:e}",

            a    = inout(reg) a,
            b    = inout(reg) b,
            c    = inout(reg) c,
            d    = inout(reg) d,
            t1   = inout(reg) t1,
            t2   = out(reg) t2,
            m    = in(reg) m,
            kg0  = const K[16] as i32,
            kg1  = const K[17] as i32,
            kg2  = const K[18] as i32,
            kg3  = const K[19] as i32,
            kg4  = const K[20] as i32,
            kg5  = const K[21] as i32,
            kg6  = const K[22] as i32,
            kg7  = const K[23] as i32,
            kg8  = const K[24] as i32,
            kg9  = const K[25] as i32,
            kg10 = const K[26] as i32,
            kg11 = const K[27] as i32,
            kg12 = const K[28] as i32,
            kg13 = const K[29] as i32,
            kg14 = const K[30] as i32,
            kg15 = const K[31] as i32,
            kh0  = const K[32] as i32,
            kh1  = const K[33] as i32,
            kh2  = const K[34] as i32,
            kh3  = const K[35] as i32,
            kh4  = const K[36] as i32,
            kh5  = const K[37] as i32,
            kh6  = const K[38] as i32,
            kh7  = const K[39] as i32,
            kh8  = const K[40] as i32,
            kh9  = const K[41] as i32,
            kh10 = const K[42] as i32,
            kh11 = const K[43] as i32,
            kh12 = const K[44] as i32,
            kh13 = const K[45] as i32,
            kh14 = const K[46] as i32,
            kh15 = const K[47] as i32,
            ki0  = const K[48] as i32,
            ki1  = const K[49] as i32,
            ki2  = const K[50] as i32,
            ki3  = const K[51] as i32,
            ki4  = const K[52] as i32,
            ki5  = const K[53] as i32,
            ki6  = const K[54] as i32,
            ki7  = const K[55] as i32,
            ki8  = const K[56] as i32,
            ki9  = const K[57] as i32,
            ki10 = const K[58] as i32,
            ki11 = const K[59] as i32,
            ki12 = const K[60] as i32,
            ki13 = const K[61] as i32,
            ki14 = const K[62] as i32,
            ki15 = const K[63] as i32,
            options(nostack),
        );
        let _ = t2;

        state[0] = sa.wrapping_add(a);
        state[1] = sb.wrapping_add(b);
        state[2] = sc.wrapping_add(c);
        state[3] = sd.wrapping_add(d);
    }
}

#[inline]
pub(super) fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}
