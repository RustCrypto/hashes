#![allow(clippy::unreadable_literal)]

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

    #[allow(clippy::needless_range_loop)]
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
