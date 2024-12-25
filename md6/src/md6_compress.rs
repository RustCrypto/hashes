use crate::md6_consts::*;

const w: usize = md6_w; // number of bits in a word (64)
const c: usize = md6_c; // size of compression output in words (16)
const n: usize = md6_n; // size of compression input block in words (89)
const q: usize = md6_q; // Q words in a compression block (>= 0) (15)
const k: usize = md6_k; // key words per compression block (>= 0) (8)
const u: usize = md6_u; // words for unique node ID (0 or 64/w)
const v: usize = md6_v; // words for control word (0 or 64/w)
const b: usize = md6_b; // data words per compression block (> 0) (64)

const t0: usize = 17; // index for linear feedback
const t1: usize = 18; // index for first input to first and
const t2: usize = 21; // index for second input to first and
const t3: usize = 31; // index for first input to second and
const t4: usize = 67; // index for second input to second and
const t5: usize = 89; // last tap

/// Macro to call loop bodies based on the value of `w`.
///
/// This macro takes three arguments:
/// - `w`: The md6_word parameter which determines the set of loop bodies to call.
/// - `S`: A round constant passed to the `loop_body` macro.
/// - `i`: An index passed to the `loop_body` macro.
///
/// Depending on the value of `w`, this macro will call a specific set of `loop_body` invocations
/// with predefined parameters. The possible values for `w` are 64, 32, 16, and 8. Each value
/// corresponds to a different set of `loop_body` calls with specific parameters.
///
/// # Parameters
/// - `w`: The md6_word parameter (must be one of 64, 32, 16, or 8).
/// - `S`: A round constant to be passed to each `loop_body` call.
/// - `i`: An index to be passed to each `loop_body` call.
macro_rules! call_loop_bodies {
    ($w: ident, $S: expr, $i: expr) => {
        if $w == 64 {
            loop_body!(10, 11, 0, $S, $i);
            loop_body!(5, 24, 1, $S, $i);
            loop_body!(13, 9, 2, $S, $i);
            loop_body!(10, 16, 3, $S, $i);
            loop_body!(11, 15, 4, $S, $i);
            loop_body!(12, 9, 5, $S, $i);
            loop_body!(2, 27, 6, $S, $i);
            loop_body!(7, 15, 7, $S, $i);
            loop_body!(14, 6, 8, $S, $i);
            loop_body!(15, 2, 9, $S, $i);
            loop_body!(7, 29, 10, $S, $i);
            loop_body!(13, 8, 11, $S, $i);
            loop_body!(11, 15, 12, $S, $i);
            loop_body!(7, 5, 13, $S, $i);
            loop_body!(6, 31, 14, $S, $i);
            loop_body!(12, 9, 15, $S, $i);
        } else if $w == 32 {
            loop_body!(5, 4, 0, $S, $i);
            loop_body!(3, 7, 1, $S, $i);
            loop_body!(6, 7, 2, $S, $i);
            loop_body!(5, 9, 3, $S, $i);
            loop_body!(4, 13, 4, $S, $i);
            loop_body!(6, 8, 5, $S, $i);
            loop_body!(7, 4, 6, $S, $i);
            loop_body!(3, 14, 7, $S, $i);
            loop_body!(5, 7, 8, $S, $i);
            loop_body!(6, 4, 9, $S, $i);
            loop_body!(5, 8, 10, $S, $i);
            loop_body!(5, 11, 11, $S, $i);
            loop_body!(4, 5, 12, $S, $i);
            loop_body!(6, 8, 13, $S, $i);
            loop_body!(7, 2, 14, $S, $i);
            loop_body!(5, 11, 15, $S, $i);
        } else if $w == 16 {
            loop_body!(5, 6, 0, $S, $i);
            loop_body!(4, 7, 1, $S, $i);
            loop_body!(3, 2, 2, $S, $i);
            loop_body!(5, 4, 3, $S, $i);
            loop_body!(7, 2, 4, $S, $i);
            loop_body!(5, 6, 5, $S, $i);
            loop_body!(5, 3, 6, $S, $i);
            loop_body!(2, 7, 7, $S, $i);
            loop_body!(4, 5, 8, $S, $i);
            loop_body!(3, 7, 9, $S, $i);
            loop_body!(4, 6, 10, $S, $i);
            loop_body!(3, 5, 11, $S, $i);
            loop_body!(4, 5, 12, $S, $i);
            loop_body!(7, 6, 13, $S, $i);
            loop_body!(7, 4, 14, $S, $i);
            loop_body!(2, 3, 15, $S, $i);
        } else if $w == 8 {
            loop_body!(3, 2, 0, $S, $i);
            loop_body!(3, 4, 1, $S, $i);
            loop_body!(3, 2, 2, $S, $i);
            loop_body!(4, 3, 3, $S, $i);
            loop_body!(3, 2, 4, $S, $i);
            loop_body!(3, 2, 5, $S, $i);
            loop_body!(3, 2, 6, $S, $i);
            loop_body!(3, 4, 7, $S, $i);
            loop_body!(2, 3, 8, $S, $i);
            loop_body!(2, 3, 9, $S, $i);
            loop_body!(3, 2, 10, $S, $i);
            loop_body!(2, 3, 11, $S, $i);
            loop_body!(2, 3, 12, $S, $i);
            loop_body!(3, 4, 13, $S, $i);
            loop_body!(2, 3, 14, $S, $i);
            loop_body!(3, 4, 15, $S, $i);
        }
    };
}

/// Returns the initial values for `S` and `Smask` based on the width `ws`.
///
/// # Parameters
/// - `ws`: The width parameter (must be one of 64, 32, 16, or 8).
///
/// # Returns
/// A tuple containing the initial values for `S` and `Smask`.
///
/// # Panics
/// Panics if `ws` is not one of the expected values.
fn get_S_vals(ws: usize) -> (md6_word, md6_word) {
    match ws {
        64 => (0x0123456789abcdef, 0x7311c2812425cfa0),
        32 => (0x01234567, 0x7311c281),
        16 => (0x01234, 0x7311),
        8 => (0x01, 0x73),
        _ => panic!("bad w"),
    }
}

/// Main compression loop for MD6.
///
/// This function performs the main compression loop for the MD6 hash function.
///
/// # Parameters
/// - `A`: A mutable reference to a vector of `md6_word` values.
/// - `r`: The number of rounds to perform.
fn md6_main_compression_loop(A: &mut Vec<md6_word>, r: usize) {
    macro_rules! loop_body {
        ($rs: expr, $ls: expr, $step: expr, $S: expr, $i: expr) => {
            let mut x = $S; // feedback constant 
            x ^= A[$i + $step - t5]; // end-around feedback
            x ^= A[$i + $step - t0]; // linear feedback
            x ^= (A[$i + $step - t1] & A[$i + $step - t2]); // first quadratic term
            x ^= (A[$i + $step - t3] & A[$i + $step - t4]); // second quadratic term
            x ^= x >> $rs; // right shift
            A[$i + $step] = x ^ (x << $ls); // left shift
        };
    }

    // Get the initial values for `S` and `Smask` based on the width `w`.
    let (mut S, Smask) = get_S_vals(w);

    let mut i = n;
    let mut j = 0;

    while j < r * c {
        // Call the loop bodies based on the value of `w`.
        // This will perform the main computation for each step in the compression loop.
        call_loop_bodies!(w, S, i);

        // Advance round constant S to the next round constant.
        S = (S << 1) ^ (S >> (w - 1)) ^ (S & Smask);
        i += 16;
        j += c;
    }
}

/// Compresses the input data using the MD6 compression function.
///
/// # Parameters
/// - `C`: A mutable reference to a vector of `md6_word` values (output).
/// - `N`: A mutable reference to a vector of `md6_word` values (input).
/// - `r`: The number of rounds to perform.
/// - `A`: A mutable reference to a vector of `md6_word` values (working space).
///
/// # Panics
/// Panics if any of the input vectors are empty or if `r` exceeds `md6_max_r`.
pub fn md6_compress(C: &mut Vec<md6_word>, N: &mut Vec<md6_word>, r: usize, A: &mut Vec<md6_word>) {
    // check that the input is sensible
    assert!(!N.is_empty());
    assert!(!C.is_empty());
    assert!(r <= md6_max_r);
    assert!(!A.is_empty());

    A[..N.len()].copy_from_slice(&N); // copy N to front of A

    md6_main_compression_loop(A, r); // do the main computation

    C.copy_from_slice(&A[((r - 1) * c + n)..((r - 1) * c + n + c)]); // output into C
}

/// Creates a control word for the MD6 hash function.
///
/// # Parameters
/// - `r`: The number of rounds.
/// - `L`: The level of the node.
/// - `z`: The final node indicator.
/// - `p`: The padding length.
/// - `keylen`: The length of the key.
/// - `d`: The digest length.
///
/// # Returns
/// The control word as an `md6_control_word`.
fn md6_make_control_word(
    r: usize,
    L: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
) -> md6_control_word {
    let V = (0 as md6_control_word) << 60 // reserved width 4 bits
        | (r as md6_control_word) << 48 // r width 12 bits
        | (L as md6_control_word) << 40 // L width 8 bits
        | (z as md6_control_word) << 36 // z width 4 bits
        | (p as md6_control_word) << 20 // p width 16 bits
        | (keylen as md6_control_word) << 12 // keylen width 8 bits
        | (d as md6_control_word); // d width 12 bits
    V
}

/// Creates a node ID for the MD6 hash function.
///
/// # Parameters
/// - `ell`: The level of the node.
/// - `i`: The index of the node.
///
/// # Returns
/// The node ID as an `md6_nodeID`.
pub fn md6_make_nodeID(ell: usize, i: md6_word) -> md6_nodeID {
    let U: md6_nodeID = (ell as md6_nodeID) << 56 | i; // ell width 8 bits, i width 56 bits

    U
}

/// Packs the input data into the `N` vector for the MD6 compression function.
///
/// # Parameters
/// - `N`: A mutable reference to a vector of `md6_word` values (output).
/// - `Q`: A vector of `md6_word` values (input).
/// - `K`: An array of `md6_word` values (key).
/// - `ell`: The level of the node.
/// - `i`: The index of the node.
/// - `r`: The number of rounds.
/// - `L`: The level of the node.
/// - `z`: The final node indicator.
/// - `p`: The padding length.
/// - `keylen`: The length of the key.
/// - `d`: The digest length.
/// - `B`: An array of `md6_word` values (input block).
pub fn md6_pack(
    N: &mut Vec<md6_word>,
    Q: Vec<md6_word>,
    K: [md6_word; k],
    ell: usize,
    i: md6_word,
    r: usize,
    L: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
    B: [md6_word; 64],
) {
    let mut ni = 0;

    N[ni..ni + q].copy_from_slice(&Q[..q]); // Q: Q in words     0--14
    ni += q;

    N[ni..ni + k].copy_from_slice(&K[..k]); // K: key in words  15--22
    ni += k;

    let U = md6_make_nodeID(ell, i); // U: unique node ID in 23
    N[ni] = U;
    ni += u;

    let V = md6_make_control_word(r, L, z, p, keylen, d); // V: control word in 24
    N[ni] = V;
    ni += v;

    N[ni..ni + b].copy_from_slice(&B[..b]); // B: data words     25--88
}

/// Standard compression function for the MD6 hash function.
///
/// # Parameters
/// - `C`: A mutable reference to a vector of `md6_word` values (output).
/// - `Q`: A vector of `md6_word` values (input).
/// - `K`: An array of `md6_word` values (key).
/// - `ell`: The level of the node.
/// - `i`: The index of the node.
/// - `r`: The number of rounds.
/// - `L`: The level of the node.
/// - `z`: The final node indicator.
/// - `p`: The padding length.
/// - `keylen`: The length of the key.
/// - `d`: The digest length.
/// - `B`: An array of `md6_word` values (input block).
///
/// # Panics
/// Panics if any of the input vectors are empty or if any of the parameters are out of range.
pub fn md6_standard_compress(
    C: &mut Vec<md6_word>,
    Q: Vec<md6_word>,
    K: [md6_word; k],
    ell: usize,
    i: md6_word,
    r: usize,
    L: usize,
    z: usize,
    p: usize,
    keylen: usize,
    d: usize,
    B: [md6_word; 64],
) {
    let mut N = vec![0; md6_n];
    let mut A = vec![0; 5000];

    // check that the input values are sensible
    assert!(!C.is_empty());
    assert!(!Q.is_empty());
    assert!(!B.is_empty());
    assert!(r <= md6_max_r);
    assert!(L <= 255);
    assert!(ell <= 255);
    assert!(p <= b * w);
    assert!(d <= c * w / 2);
    assert!(!K.is_empty());

    md6_pack(&mut N, Q, K, ell, i, r, L, z, p, keylen, d, B); // pack input data into N

    md6_compress(C, &mut N, r, &mut A); // compress
}
