use byte_tools::{write_u64v_le, read_u64v_le};
use generic_array::GenericArray;
use generic_array::typenum::U200;

use consts::{RC, ROTC, PIL, M5};

/// Code based on Keccak-compact64.c from ref implementation.
pub fn f(state: &mut GenericArray<u8, U200>) {
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
            t[0] = c[M5[x + 4]] ^ c[M5[x + 1]].rotate_left(1);
            for y in 0..5 {
                s[y * 5 + x] ^= t[0];
            }
        }

        // Rho Pi
        t[0] = s[1];
        for x in 0..24 {
            c[0] = s[PIL[x]];
            s[PIL[x]] = t[0].rotate_left(ROTC[x] as u32);
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
