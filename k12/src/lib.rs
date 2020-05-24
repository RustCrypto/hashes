//! An implementation of the KangarooTwelve cryptographic hash algorithm,
//! based on the reference implementation:
//!
//! <https://github.com/gvanas/KeccakCodePackage/blob/master/Standalone/kangaroo_twelve-reference/K12.py>
//!
//! Some optimisations copied from: <https://github.com/RustCrypto/hashes/tree/master/sha3/src>

use std::cmp::min;

#[macro_use]
mod macros {
    /// Copied from `arrayref` crate
    macro_rules! array_ref {
        ($arr:expr, $offset:expr, $len:expr) => {{
            {
                #[inline]
                unsafe fn as_array<T>(slice: &[T]) -> &[T; $len] {
                    &*(slice.as_ptr() as *const [_; $len])
                }
                let offset = $offset;
                let slice = &$arr[offset..offset + $len];
                unsafe { as_array(slice) }
            }
        }};
    }

    macro_rules! REPEAT4 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! REPEAT5 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! REPEAT6 {
        ($e: expr) => {
            $e;
            $e;
            $e;
            $e;
            $e;
            $e;
        };
    }

    macro_rules! REPEAT24 {
        ($e: expr, $s: expr) => {
            REPEAT6!({
                $e;
                $s;
            });
            REPEAT6!({
                $e;
                $s;
            });
            REPEAT6!({
                $e;
                $s;
            });
            REPEAT5!({
                $e;
                $s;
            });
            $e;
        };
    }

    macro_rules! FOR5 {
        ($v: expr, $s: expr, $e: expr) => {
            $v = 0;
            REPEAT4!({
                $e;
                $v += $s;
            });
            $e;
        };
    }
}

mod lanes {
    pub const RC: [u64; 12] = [
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
        0x8000000080008008,
    ];

    // (0..24).map(|t| ((t+1)*(t+2)/2) % 64)
    pub const RHO: [u32; 24] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];
    pub const PI: [usize; 24] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    pub fn keccak(lanes: &mut [u64; 25]) {
        let mut c = [0u64; 5];
        let (mut x, mut y): (usize, usize);

        for round in 0..12 {
            // θ
            FOR5!(x, 1, {
                c[x] = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
            });

            FOR5!(x, 1, {
                FOR5!(y, 5, {
                    lanes[x + y] ^= c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                });
            });

            // ρ and π
            let mut a = lanes[1];
            x = 0;
            REPEAT24!(
                {
                    c[0] = lanes[PI[x]];
                    lanes[PI[x]] = a.rotate_left(RHO[x]);
                },
                {
                    a = c[0];
                    x += 1;
                }
            );

            // χ
            FOR5!(y, 5, {
                FOR5!(x, 1, {
                    c[x] = lanes[x + y];
                });
                FOR5!(x, 1, {
                    lanes[x + y] = c[x] ^ ((!c[(x + 1) % 5]) & c[(x + 2) % 5]);
                });
            });

            // ι
            lanes[0] ^= RC[round];
        }
    }
}

fn read_u64(bytes: &[u8; 8]) -> u64 {
    unsafe { *(bytes as *const [u8; 8] as *const u64) }.to_le()
}
fn write_u64(val: u64) -> [u8; 8] {
    unsafe { *(&val.to_le() as *const u64 as *const [u8; 8]) }
}

fn keccak(state: &mut [u8; 200]) {
    let mut lanes = [0u64; 25];
    let mut y;
    for x in 0..5 {
        FOR5!(y, 5, {
            lanes[x + y] = read_u64(array_ref!(state, 8 * (x + y), 8));
        });
    }
    lanes::keccak(&mut lanes);
    for x in 0..5 {
        FOR5!(y, 5, {
            let i = 8 * (x + y);
            state[i..i + 8].copy_from_slice(&write_u64(lanes[x + y]));
        });
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

/// Hash the `input` message, with the given `customization` string, to `output_len` bytes.
pub fn kangaroo_twelve(
    input: impl AsRef<[u8]>,
    customization: impl AsRef<[u8]>,
    output_len: usize,
) -> Vec<u8> {
    let b = 8192;
    let c = 256;

    let mut slice = Vec::new(); // S
    slice.extend_from_slice(input.as_ref());
    slice.extend_from_slice(customization.as_ref());
    slice.extend_from_slice(&right_encode(customization.as_ref().len())[..]);

    // === Cut the input string into chunks of b bytes ===
    let n = (slice.len() + b - 1) / b;
    let mut slices = Vec::with_capacity(n); // Si
    for i in 0..n {
        let ub = min((i + 1) * b, slice.len());
        slices.push(&slice[i * b..ub]);
    }

    if n == 1 {
        // === Process the tree with only a final node ===
        f(slices[0], 0x07, output_len)
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
        for i in 0..n - 1 {
            node_star.extend_from_slice(&intermediate[i][..]);
        }
        node_star.extend_from_slice(&right_encode(n - 1));
        node_star.extend_from_slice(b"\xFF\xFF");

        f(&node_star[..], 0x06, output_len)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter;

    fn read_bytes<T: AsRef<[u8]>>(s: T) -> Vec<u8> {
        fn b(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => unreachable!(),
            }
        }
        let s = s.as_ref();
        let mut i = 0;
        let mut v = Vec::new();
        while i < s.len() {
            if s[i] == b' ' || s[i] == b'\n' {
                i += 1;
                continue;
            }

            let n = b(s[i]) * 16 + b(s[i + 1]);
            v.push(n);
            i += 2;
        }
        v
    }

    #[test]
    fn empty() {
        // Source: reference paper
        assert_eq!(
            kangaroo_twelve("", "", 32),
            read_bytes(
                "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca
                1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5"
            )
        );

        assert_eq!(
            kangaroo_twelve("", "", 64),
            read_bytes(
                "1a c2 d4 50 fc 3b 42 05 d1 9d a7 bf ca
                1b 37 51 3c 08 03 57 7a c7 16 7f 06 fe 2c e1 f0 ef 39 e5 42 69 c0 56 b8 c8 2e
                48 27 60 38 b6 d2 92 96 6c c0 7a 3d 46 45 27 2e 31 ff 38 50 81 39 eb 0a 71"
            )
        );

        assert_eq!(
            kangaroo_twelve("", "", 10032)[10000..],
            read_bytes(
                "e8 dc 56 36 42 f7 22 8c 84
                68 4c 89 84 05 d3 a8 34 79 91 58 c0 79 b1 28 80 27 7a 1d 28 e2 ff 6d"
            )[..]
        );
    }

    #[test]
    fn pat_m() {
        let expected = [
            "2b da 92 45 0e 8b 14 7f 8a 7c b6 29 e7 84 a0 58 ef ca 7c f7
                d8 21 8e 02 d3 45 df aa 65 24 4a 1f",
            "6b f7 5f a2 23 91 98 db 47 72 e3 64 78 f8 e1 9b 0f 37 12 05
                f6 a9 a9 3a 27 3f 51 df 37 12 28 88",
            "0c 31 5e bc de db f6 14 26 de 7d cf 8f b7 25 d1 e7 46 75 d7
                f5 32 7a 50 67 f3 67 b1 08 ec b6 7c",
            "cb 55 2e 2e c7 7d 99 10 70 1d 57 8b 45 7d df 77 2c 12 e3 22
                e4 ee 7f e4 17 f9 2c 75 8f 0d 59 d0",
            "87 01 04 5e 22 20 53 45 ff 4d da 05 55 5c bb 5c 3a f1 a7 71
                c2 b8 9b ae f3 7d b4 3d 99 98 b9 fe",
            "84 4d 61 09 33 b1 b9 96 3c bd eb 5a e3 b6 b0 5c c7 cb d6 7c
                ee df 88 3e b6 78 a0 a8 e0 37 16 82",
            "3c 39 07 82 a8 a4 e8 9f a6 36 7f 72 fe aa f1 32 55 c8 d9 58
                78 48 1d 3c d8 ce 85 f5 8e 88 0a f8",
        ];
        for i in 0..5
        /*NOTE: can be up to 7 but is slow*/
        {
            let len = 17usize.pow(i);
            let m: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
            let result = kangaroo_twelve(m, "", 32);
            assert_eq!(result, read_bytes(expected[i as usize]));
        }
    }

    #[test]
    fn pat_c() {
        let expected = [
            "fa b6 58 db 63 e9 4a 24 61 88 bf 7a f6 9a 13 30 45 f4 6e e9
                84 c5 6e 3c 33 28 ca af 1a a1 a5 83",
            "d8 48 c5 06 8c ed 73 6f 44 62 15 9b 98 67 fd 4c 20 b8 08 ac
                c3 d5 bc 48 e0 b0 6b a0 a3 76 2e c4",
            "c3 89 e5 00 9a e5 71 20 85 4c 2e 8c 64 67 0a c0 13 58 cf 4c
                1b af 89 44 7a 72 42 34 dc 7c ed 74",
            "75 d2 f8 6a 2e 64 45 66 72 6b 4f bc fc 56 57 b9 db cf 07 0c
                7b 0d ca 06 45 0a b2 91 d7 44 3b cf",
        ];
        for i in 0..4 {
            let m: Vec<u8> = iter::repeat(0xFF).take(2usize.pow(i) - 1).collect();
            let len = 41usize.pow(i);
            let c: Vec<u8> = (0..len).map(|j| (j % 251) as u8).collect();
            let result = kangaroo_twelve(m, c, 32);
            assert_eq!(result, read_bytes(expected[i as usize]));
        }
    }
}
