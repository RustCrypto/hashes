/// HAS-160 compression function.
/// Processes 64-byte blocks, updating the 5-word state in place.
/// Words are interpreted as little-endian u32 values. The schedule
/// consists of the initial 16 words plus 16 derived XOR words.
pub fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) {
    for block in blocks {
        compress_block(state, block);
    }
}

fn compress_block(hash: &mut [u32; 5], block: &[u8; 64]) {
    // Load 16 little-endian 32-bit words
    let mut x = [0u32; 32];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        x[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    // Derive words 16..31
    x[16] = x[0] ^ x[1] ^ x[2] ^ x[3]; // rounds  1..20
    x[17] = x[4] ^ x[5] ^ x[6] ^ x[7];
    x[18] = x[8] ^ x[9] ^ x[10] ^ x[11];
    x[19] = x[12] ^ x[13] ^ x[14] ^ x[15];
    x[20] = x[3] ^ x[6] ^ x[9] ^ x[12]; // rounds 21..40
    x[21] = x[2] ^ x[5] ^ x[8] ^ x[15];
    x[22] = x[1] ^ x[4] ^ x[11] ^ x[14];
    x[23] = x[0] ^ x[7] ^ x[10] ^ x[13];
    x[24] = x[5] ^ x[7] ^ x[12] ^ x[14]; // rounds 41..60
    x[25] = x[0] ^ x[2] ^ x[9] ^ x[11];
    x[26] = x[4] ^ x[6] ^ x[13] ^ x[15];
    x[27] = x[1] ^ x[3] ^ x[8] ^ x[10];
    x[28] = x[2] ^ x[7] ^ x[8] ^ x[13]; // rounds 61..80
    x[29] = x[3] ^ x[4] ^ x[9] ^ x[14];
    x[30] = x[0] ^ x[5] ^ x[10] ^ x[15];
    x[31] = x[1] ^ x[6] ^ x[11] ^ x[12];

    // Working variables
    let mut a = hash[0];
    let mut b = hash[1];
    let mut c = hash[2];
    let mut d = hash[3];
    let mut e = hash[4];

    macro_rules! step_f1 {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$msg:expr,$rot:expr) => {{
            $E = $E
                .wrapping_add($A.rotate_left($rot))
                .wrapping_add($D ^ ($B & ($C ^ $D)))
                .wrapping_add($msg);
            $B = $B.rotate_left(10);
        }};
    }
    macro_rules! step_f2 {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$msg:expr,$rot:expr) => {{
            $E = $E
                .wrapping_add($A.rotate_left($rot))
                .wrapping_add($B ^ $C ^ $D)
                .wrapping_add($msg)
                .wrapping_add(0x5A827999);
            $B = $B.rotate_left(17);
        }};
    }
    macro_rules! step_f3 {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$msg:expr,$rot:expr) => {{
            $E = $E
                .wrapping_add($A.rotate_left($rot))
                .wrapping_add($C ^ ($B | !$D))
                .wrapping_add($msg)
                .wrapping_add(0x6ED9EBA1);
            $B = $B.rotate_left(25);
        }};
    }
    macro_rules! step_f4 {
        ($A:ident,$B:ident,$C:ident,$D:ident,$E:ident,$msg:expr,$rot:expr) => {{
            $E = $E
                .wrapping_add($A.rotate_left($rot))
                .wrapping_add($B ^ $C ^ $D)
                .wrapping_add($msg)
                .wrapping_add(0x8F1BBCDC);
            $B = $B.rotate_left(30);
        }};
    }

    // Group F1 (rounds 1..20)
    step_f1!(a, b, c, d, e, x[18], 5);
    step_f1!(e, a, b, c, d, x[0], 11);
    step_f1!(d, e, a, b, c, x[1], 7);
    step_f1!(c, d, e, a, b, x[2], 15);
    step_f1!(b, c, d, e, a, x[3], 6);
    step_f1!(a, b, c, d, e, x[19], 13);
    step_f1!(e, a, b, c, d, x[4], 8);
    step_f1!(d, e, a, b, c, x[5], 14);
    step_f1!(c, d, e, a, b, x[6], 7);
    step_f1!(b, c, d, e, a, x[7], 12);
    step_f1!(a, b, c, d, e, x[16], 9);
    step_f1!(e, a, b, c, d, x[8], 11);
    step_f1!(d, e, a, b, c, x[9], 8);
    step_f1!(c, d, e, a, b, x[10], 15);
    step_f1!(b, c, d, e, a, x[11], 6);
    step_f1!(a, b, c, d, e, x[17], 12);
    step_f1!(e, a, b, c, d, x[12], 9);
    step_f1!(d, e, a, b, c, x[13], 14);
    step_f1!(c, d, e, a, b, x[14], 5);
    step_f1!(b, c, d, e, a, x[15], 13);

    // Group F2 (rounds 21..40)
    step_f2!(a, b, c, d, e, x[22], 5);
    step_f2!(e, a, b, c, d, x[3], 11);
    step_f2!(d, e, a, b, c, x[6], 7);
    step_f2!(c, d, e, a, b, x[9], 15);
    step_f2!(b, c, d, e, a, x[12], 6);
    step_f2!(a, b, c, d, e, x[23], 13);
    step_f2!(e, a, b, c, d, x[15], 8);
    step_f2!(d, e, a, b, c, x[2], 14);
    step_f2!(c, d, e, a, b, x[5], 7);
    step_f2!(b, c, d, e, a, x[8], 12);
    step_f2!(a, b, c, d, e, x[20], 9);
    step_f2!(e, a, b, c, d, x[11], 11);
    step_f2!(d, e, a, b, c, x[14], 8);
    step_f2!(c, d, e, a, b, x[1], 15);
    step_f2!(b, c, d, e, a, x[4], 6);
    step_f2!(a, b, c, d, e, x[21], 12);
    step_f2!(e, a, b, c, d, x[7], 9);
    step_f2!(d, e, a, b, c, x[10], 14);
    step_f2!(c, d, e, a, b, x[13], 5);
    step_f2!(b, c, d, e, a, x[0], 13);

    // Group F3 (rounds 41..60)
    step_f3!(a, b, c, d, e, x[26], 5);
    step_f3!(e, a, b, c, d, x[12], 11);
    step_f3!(d, e, a, b, c, x[5], 7);
    step_f3!(c, d, e, a, b, x[14], 15);
    step_f3!(b, c, d, e, a, x[7], 6);
    step_f3!(a, b, c, d, e, x[27], 13);
    step_f3!(e, a, b, c, d, x[0], 8);
    step_f3!(d, e, a, b, c, x[9], 14);
    step_f3!(c, d, e, a, b, x[2], 7);
    step_f3!(b, c, d, e, a, x[11], 12);
    step_f3!(a, b, c, d, e, x[24], 9);
    step_f3!(e, a, b, c, d, x[4], 11);
    step_f3!(d, e, a, b, c, x[13], 8);
    step_f3!(c, d, e, a, b, x[6], 15);
    step_f3!(b, c, d, e, a, x[15], 6);
    step_f3!(a, b, c, d, e, x[25], 12);
    step_f3!(e, a, b, c, d, x[8], 9);
    step_f3!(d, e, a, b, c, x[1], 14);
    step_f3!(c, d, e, a, b, x[10], 5);
    step_f3!(b, c, d, e, a, x[3], 13);

    // Group F4 (rounds 61..80)
    step_f4!(a, b, c, d, e, x[30], 5);
    step_f4!(e, a, b, c, d, x[7], 11);
    step_f4!(d, e, a, b, c, x[2], 7);
    step_f4!(c, d, e, a, b, x[13], 15);
    step_f4!(b, c, d, e, a, x[8], 6);
    step_f4!(a, b, c, d, e, x[31], 13);
    step_f4!(e, a, b, c, d, x[3], 8);
    step_f4!(d, e, a, b, c, x[14], 14);
    step_f4!(c, d, e, a, b, x[9], 7);
    step_f4!(b, c, d, e, a, x[4], 12);
    step_f4!(a, b, c, d, e, x[28], 9);
    step_f4!(e, a, b, c, d, x[15], 11);
    step_f4!(d, e, a, b, c, x[10], 8);
    step_f4!(c, d, e, a, b, x[5], 15);
    step_f4!(b, c, d, e, a, x[0], 6);
    step_f4!(a, b, c, d, e, x[29], 12);
    step_f4!(e, a, b, c, d, x[11], 9);
    step_f4!(d, e, a, b, c, x[6], 14);
    step_f4!(c, d, e, a, b, x[1], 5);
    step_f4!(b, c, d, e, a, x[12], 13);

    // Update chaining state
    hash[0] = hash[0].wrapping_add(a);
    hash[1] = hash[1].wrapping_add(b);
    hash[2] = hash[2].wrapping_add(c);
    hash[3] = hash[3].wrapping_add(d);
    hash[4] = hash[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_changes_on_zero_block() {
        let mut st = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
        let before = st;
        let blk = [0u8; 64];
        compress(&mut st, &[blk]);
        assert_ne!(before, st);
    }
}
