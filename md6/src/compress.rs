use crate::consts::*;

const W: usize = MD6_W; // number of bits in a word (64)
const C: usize = MD6_C; // size of compression output in words (16)
const N: usize = MD6_N; // size of compression input block in words (89)
const Q: usize = MD6_Q; // Q words in a compression block (>= 0) (15)
const K: usize = MD6_K; // key words per compression block (>= 0) (8)
const U: usize = MD6_U; // words for unique node ID (0 or 64/w)
const V: usize = MD6_V; // words for control word (0 or 64/w)
const B: usize = MD6_B; // data words per compression block (> 0) (64)

const T0: usize = 17; // index for linear feedback
const T1: usize = 18; // index for first input to first and
const T2: usize = 21; // index for second input to first and
const T3: usize = 31; // index for first input to second and
const T4: usize = 67; // index for second input to second and
const T5: usize = 89; // last tap

macro_rules! call_loop_bodies {
    ($w: ident, $s: expr, $i: expr) => {
        if $w == 64 {
            loop_body!(10, 11, 0, $s, $i);
            loop_body!(5, 24, 1, $s, $i);
            loop_body!(13, 9, 2, $s, $i);
            loop_body!(10, 16, 3, $s, $i);
            loop_body!(11, 15, 4, $s, $i);
            loop_body!(12, 9, 5, $s, $i);
            loop_body!(2, 27, 6, $s, $i);
            loop_body!(7, 15, 7, $s, $i);
            loop_body!(14, 6, 8, $s, $i);
            loop_body!(15, 2, 9, $s, $i);
            loop_body!(7, 29, 10, $s, $i);
            loop_body!(13, 8, 11, $s, $i);
            loop_body!(11, 15, 12, $s, $i);
            loop_body!(7, 5, 13, $s, $i);
            loop_body!(6, 31, 14, $s, $i);
            loop_body!(12, 9, 15, $s, $i);
        } else if $w == 32 {
            loop_body!(5, 4, 0, $s, $i);
            loop_body!(3, 7, 1, $s, $i);
            loop_body!(6, 7, 2, $s, $i);
            loop_body!(5, 9, 3, $s, $i);
            loop_body!(4, 13, 4, $s, $i);
            loop_body!(6, 8, 5, $s, $i);
            loop_body!(7, 4, 6, $s, $i);
            loop_body!(3, 14, 7, $s, $i);
            loop_body!(5, 7, 8, $s, $i);
            loop_body!(6, 4, 9, $s, $i);
            loop_body!(5, 8, 10, $s, $i);
            loop_body!(5, 11, 11, $s, $i);
            loop_body!(4, 5, 12, $s, $i);
            loop_body!(6, 8, 13, $s, $i);
            loop_body!(7, 2, 14, $s, $i);
            loop_body!(5, 11, 15, $s, $i);
        } else if $w == 16 {
            loop_body!(5, 6, 0, $s, $i);
            loop_body!(4, 7, 1, $s, $i);
            loop_body!(3, 2, 2, $s, $i);
            loop_body!(5, 4, 3, $s, $i);
            loop_body!(7, 2, 4, $s, $i);
            loop_body!(5, 6, 5, $s, $i);
            loop_body!(5, 3, 6, $s, $i);
            loop_body!(2, 7, 7, $s, $i);
            loop_body!(4, 5, 8, $s, $i);
            loop_body!(3, 7, 9, $s, $i);
            loop_body!(4, 6, 10, $s, $i);
            loop_body!(3, 5, 11, $s, $i);
            loop_body!(4, 5, 12, $s, $i);
            loop_body!(7, 6, 13, $s, $i);
            loop_body!(7, 4, 14, $s, $i);
            loop_body!(2, 3, 15, $s, $i);
        } else if $w == 8 {
            loop_body!(3, 2, 0, $s, $i);
            loop_body!(3, 4, 1, $s, $i);
            loop_body!(3, 2, 2, $s, $i);
            loop_body!(4, 3, 3, $s, $i);
            loop_body!(3, 2, 4, $s, $i);
            loop_body!(3, 2, 5, $s, $i);
            loop_body!(3, 2, 6, $s, $i);
            loop_body!(3, 4, 7, $s, $i);
            loop_body!(2, 3, 8, $s, $i);
            loop_body!(2, 3, 9, $s, $i);
            loop_body!(3, 2, 10, $s, $i);
            loop_body!(2, 3, 11, $s, $i);
            loop_body!(2, 3, 12, $s, $i);
            loop_body!(3, 4, 13, $s, $i);
            loop_body!(2, 3, 14, $s, $i);
            loop_body!(3, 4, 15, $s, $i);
        }
    };
}

fn get_s_constants(ws: usize) -> (Md6Word, Md6Word) {
    match ws {
        64 => (0x0123456789abcdef, 0x7311c2812425cfa0),
        32 => (0x01234567, 0x7311c281),
        16 => (0x01234, 0x7311),
        8 => (0x01, 0x73),
        _ => panic!("bad w"),
    }
}

fn main_compression_loop(a: &mut [Md6Word], r: usize) {
    macro_rules! loop_body {
        ($rs: expr, $ls: expr, $step: expr, $s: expr, $i: expr) => {
            let mut x = $s; // feedback constant
            x ^= a[$i + $step - T5]; // end-around feedback
            x ^= a[$i + $step - T0]; // linear feedback
            x ^= (a[$i + $step - T1] & a[$i + $step - T2]); // first quadratic term
            x ^= (a[$i + $step - T3] & a[$i + $step - T4]); // second quadratic term
            x ^= x >> $rs; // right shift
            a[$i + $step] = x ^ (x << $ls); // left shift
        };
    }

    // Get the initial values for `s` and `smask` based on the width `w`.
    let (mut s, smask) = get_s_constants(W);

    let mut i = N;
    let mut j = 0;

    while j < r * C {
        // Call the loop bodies based on the value of `w`.
        // This will perform the main computation for each step in the compression loop.
        call_loop_bodies!(W, s, i);

        // Advance round constant s to the next round constant.
        s = (s << 1) ^ (s >> (W - 1)) ^ (s & smask);
        i += 16;
        j += C;
    }
}

pub fn compress(c: &mut [Md6Word], n: &mut [Md6Word], r: usize, a: &mut [Md6Word]) {
    // check that the input is sensible
    assert!(!n.is_empty());
    assert!(!n.is_empty());
    assert!(r <= MD6_MAX_R);
    assert!(!a.is_empty());

    a[..n.len()].copy_from_slice(n); // copy n to front of a

    main_compression_loop(a, r); // do the main computation

    c.copy_from_slice(&a[((r - 1) * C + N)..((r - 1) * C + N + C)]); // output into c
}

fn make_control_word(
    r: usize,
    l: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
) -> Md6ControlWord {
    (0 as Md6ControlWord) << 60 // reserved width 4 bits
        | (r as Md6ControlWord) << 48 // r width 12 bits
        | (l as Md6ControlWord) << 40 // L width 8 bits
        | (z as Md6ControlWord) << 36 // z width 4 bits
        | (p as Md6ControlWord) << 20 // p width 16 bits
        | (keylen as Md6ControlWord) << 12 // keylen width 8 bits
        | (d as Md6ControlWord) // d width 12 bits
}

pub fn make_node_id(ell: usize, i: Md6Word) -> Md6NodeID {
    (ell as Md6NodeID) << 56 | i // ell width 8 bits, i width 56 bits
}

pub fn pack(
    n: &mut [Md6Word],
    q: &[Md6Word],
    k: [Md6Word; K],
    ell: usize,
    i: Md6Word,
    r: usize,
    l: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
    b: [Md6Word; 64],
) {
    let mut ni = 0;

    n[ni..ni + Q].copy_from_slice(&q[..Q]); // q: q in words     0--14
    ni += Q;

    n[ni..ni + K].copy_from_slice(&k[..K]); // k: key in words  15--22
    ni += K;

    let u = make_node_id(ell, i); // u: unique node ID in 23
    n[ni] = u;
    ni += U;

    let v = make_control_word(r, l, z, p, keylen, d); // v: control word in 24
    n[ni] = v;
    ni += V;

    n[ni..ni + B].copy_from_slice(&b[..B]); // b: data words     25--88
}

pub fn standard_compress(
    c: &mut [Md6Word],
    q: &[Md6Word],
    k: [Md6Word; K],
    ell: usize,
    i: Md6Word,
    r: usize,
    l: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
    b: [Md6Word; 64],
) {
    let mut n = [0; MD6_N];
    let mut a = [0; 5000];

    // check that the input values are sensible
    assert!(!c.is_empty());
    assert!(!q.is_empty());
    assert!(!b.is_empty());
    assert!(r <= MD6_MAX_R);
    assert!(l <= 255);
    assert!(ell <= 255);
    assert!(p <= B * W);
    assert!(d <= C * W / 2);
    assert!(!k.is_empty());

    pack(&mut n, q, k, ell, i, r, l, z, p, keylen, d, b); // pack input data into N

    compress(c, &mut n, r, &mut a); // compress
}
