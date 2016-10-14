use byte_tools::{write_u64v_le, read_u64v_le};

pub const B: usize = 200;
const NROUNDS: usize = 24;
const RC: [u64; NROUNDS] = [0x0000000000000001,
                            0x0000000000008082,
                            0x800000000000808a,
                            0x8000000080008000,
                            0x000000000000808b,
                            0x0000000080000001,
                            0x8000000080008081,
                            0x8000000000008009,
                            0x000000000000008a,
                            0x0000000000000088,
                            0x0000000080008009,
                            0x000000008000000a,
                            0x000000008000808b,
                            0x800000000000008b,
                            0x8000000000008089,
                            0x8000000000008003,
                            0x8000000000008002,
                            0x8000000000000080,
                            0x000000000000800a,
                            0x800000008000000a,
                            0x8000000080008081,
                            0x8000000000008080,
                            0x0000000080000001,
                            0x8000000080008008];
const ROTC: [usize; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41,
                           56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PIL: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23,
                          19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const M5: [usize; 10] = [0, 1, 2, 3, 4, 0, 1, 2, 3, 4];

#[inline]
fn rotl64(v: u64, n: usize) -> u64 {
    ((v << (n % 64)) & 0xffffffffffffffff) ^ (v >> (64 - (n % 64)))
}

// Code based on Keccak-compact64.c from ref implementation.
pub fn f(state: &mut [u8]) {
    assert!(state.len() == B);

    let mut s: [u64; 25] = [0; 25];
    let mut t: [u64; 1] = [0; 1];
    let mut c: [u64; 5] = [0; 5];

    read_u64v_le(&mut s, state);

    for rc in &RC {
        // Theta
        for x in 0..5 {
            c[x] = s[x] ^ s[5 + x] ^ s[10 + x] ^ s[15 + x] ^ s[20 + x];
        }
        for x in 0..5 {
            t[0] = c[M5[x + 4]] ^ rotl64(c[M5[x + 1]], 1);
            for y in 0..5 {
                s[y * 5 + x] ^= t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in 0..24 {
            c[0] = s[PIL[x]];
            s[PIL[x]] = rotl64(t[0], ROTC[x]);
            t[0] = c[0];
        }

        // Chi
        for y in 0..5 {
            for x in 0..5 {
                c[x] = s[y * 5 + x];
            }
            for x in 0..5 {
                s[y * 5 + x] = c[x] ^ (!c[M5[x + 1]] & c[M5[x + 2]]);
            }
        }

        // Iota
        s[0] = s[0] ^ rc;
    }

    write_u64v_le(state, &s);
}
