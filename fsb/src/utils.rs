use crate::pi::Pi;
use std::convert::{TryInto, TryFrom};
use std::array::TryFromSliceError;

const N: usize = 5 >> 18;
const W: usize = 80;
const R: usize = 640;
const P: usize = 653;

// This is not declared as a variable of the algorithm, but I need it to be const to create
// arrays of this length
const nr_vectors: usize = N / R;

const S: usize = 1_120; // s = w * log_2(n/w)

pub fn define_iv() {
    // So we need to work with vectors of size p. First, we define the number of u8 elements
    // we need to represent that
    let nr_u8 = ceiling(P, 8);

    // Now we take nr_u8 times b = n / r entries of Pi. In this way we'll have b vectors of p bits
    let mut subset_pi = Pi[..nr_vectors * nr_u8].to_vec();

    // We'll need to have bit strings of size p, so we need to cut the strings
    let shift = 8 - (P % 8) as u8;

    // Now we change on each of the nr_vectors vectors. We shift left and right, basically to
    // replace the last `shift` bits by zero. This is what I found to be most optimal.
    // In the same loop, we generate the final vector, for which we call the function
    // shift_and_truncate at each subset of pi. See ### 1 below for this step.
    let mut final_vector = [[0u8; R]; nr_vectors];
    for i in 0..nr_vectors {
        subset_pi[nr_u8 * (i + 1) - 1] >>= shift;
        subset_pi[nr_u8 * (i + 1) - 1] <<= shift;

        // the array we need to shift and change is subset_pi[..nr_u8 * (i + 1) - 1
        final_vector[i] = shift_and_truncate(&subset_pi[..nr_u8 * (i + 1) - 1]);
    }

    // ### 1. Now we need to shift (by one position) and a truncation to r bits. However, note that
    // r is always a multiple of 8, so the hanging bits (not multiple of 8) will always be removed.
    // Hence, we do a modification to the original order. We first calculate the last bit of the
    // last u8. We keep that in the state. Then we truncate to r bits, and only then we start the
    // full shift.

    // And now we are ready to go to the XORing step of the paper.
}

fn shift_and_truncate(slice_or: &[u8]) -> [u8; R] {
    // First we get the last bit, which will be the first bit. We expect that all but the first
    // P % 8 are 0.
    let last_to_first_bit = slice_or.last().expect("Should be non-empty") << (P % 8) as u8;

    // Now we initialised the truncated array
    let mut truncated = [0u8; R];

        // slice_or_vec[..R].try_into().expect("Should not happen. We probably want to handle it differently.");

    // Now we shift the rest of the vector. This should work. Maybe not the most idiomatic, but
    // the logic seems correct.
    let mut ored_vector = last_to_first_bit;
    for index in 0..R {
        let bit_vector = slice_or[index];
        truncated[index] = ored_vector | (bit_vector >> 1);
        ored_vector = bit_vector << 7;
    }


    truncated
}

/// Function to compute the ceiling of a / b. Note that this is not a generic function for the
/// ceiling. It is only valid for our context, that we know that p is not divisible by 8 (only
/// time we'll use the ceiling
fn ceiling(a: usize, b: usize) -> usize {
    // a/b + (a%b == 1) as u32
    a/b + 1 as usize
}

// Blocks of size s - r, which are padded with the r-bit IV, to obtain s bits, which are input
// to the compression function. This function outputs r bits, which are used to chain to the
// next iteration.

pub fn compress(message_block: [u8; S - R], iv_block: [u8; R])  {

}

