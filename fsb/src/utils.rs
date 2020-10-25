#![allow(non_snake_case)]

use crate::pi::Pi;
use std::convert::{TryInto, TryFrom};
use std::array::TryFromSliceError;
use std::os::macos::raw::pthread_t;
use whirlpool::{Whirlpool, Digest};

use std::str;

const N: usize = 5 >> 18;
const W: usize = 80;
const R: usize = 640;
const P: usize = 653;
const OUTPUT_SIZE: usize = 160;

// This is not declared as a variable of the algorithm, but I need it to be const to create
// arrays of this length
const NR_VECTORS: usize = N / R;

// Again, this is not declared as variable in the algorithm. For now let's keep it this way.
// Note that this is computing the ceiling (we now that P is not divisible by 8, never).
const SIZE_VECTORS: usize = P / 8 + 1;

const S: usize = 1_120; // s = w * log_2(n/w)

pub fn define_iv(index: usize) -> [u8; SIZE_VECTORS] {
    // Now we take SIZE_VECTORS times b = n / r entries of Pi. In this way we'll have b vectors of p bits
    let mut subset_pi: [u8; SIZE_VECTORS] = [0u8; SIZE_VECTORS];
    subset_pi.copy_from_slice(&Pi[index * SIZE_VECTORS..(index + 1) * SIZE_VECTORS]);

    // We'll need to have bit strings of size p, so we need to cut the strings
    // todo: this can be a constant
    let shift = 8 - (P % 8) as u8;

    // Now we change on each of the nr_vectors vectors. We shift right and left, basically to
    // replace the last `shift` bits by zero. This is what I found to be most optimal.
    if let Some(last) = subset_pi.last_mut() {
        *last >>= shift;
        *last <<= shift;
    }

    subset_pi
}

/// Vector XORing. Given the s input bits of the function, we derive a set of w indexes
/// $(W_i)_{i\in[0;w-1]}$ between $0$ and $n - 1$. The value of each $W_i$ is computed
/// from the inputs bits like this:
/// $W_i = i \times (n / w) + IV_i + M_i \times 2^{r / w}.
/// todo: verify that the output type is what is expected. Maybe we don't need such a big
/// integer.
fn computing_W_indices(input_vector: [u8; R], message: [u8; S - R]) -> [u128; W] {
    let mut W_indices: [u128; W] = [0; W];
    let divided_message: [u8; W] = dividing_bits(&message, (S-R)/W);
    // todo: we are clearly delcaring unnecesary variables. For the moment keep for readability.
    for i in 0..W {
        let input_vector_i = input_vector[i]; // r/w is always 8, see table 3
        let message_i = divided_message[i];

        W_indices[i] = ((i * N/W) as u128 + input_vector_i as u128 +
                           (message_i << (R/W) as u8) as u128);
    }

    W_indices

    // then we take vector floor(W_i / r), we shift it to the right >> W_i mod r positions,
    // and truncate it to r bits (why the truncation?). We XOR these values for the
    // w values.
}

/// This function servers the purpose presented in table 3, of breaking a bit array into
/// batches of size not multiple of 8. Note that the IV will be broken always in size 8, which
/// is quite convenient. Also, the only numbers we'll have to worry for are 5 and 6.
fn dividing_bits(input_bits: &[u8], size_batches: usize) -> [u8; W] {
    if size_batches > 6 {
        panic!("Expecting batches of size 5 or 6. Other values do not follow \
        the standard specification")
    }

    let mut new_bits = [0u8; W];
    let shifting_factor = (8 - size_batches) as u8;
    for i in 0..W {
        let position = i * size_batches ;
        let initial_byte = position / 8;
        let initial_bit = position % 8;
        let switch = (initial_bit + size_batches - 1) / 8; // check if we use the next byte

        // Might be a better way to do this function
        if switch == 1 {
            new_bits[i] = (input_bits[initial_byte] << initial_bit as u8 |
                input_bits[initial_byte + 1] >> ( 8 - initial_bit as u8)) >> shifting_factor;
        }
        else {
            new_bits[i] = (input_bits[initial_byte] << initial_bit as u8) >> shifting_factor;
        }

    }

    new_bits
}

/// Blocks of size s - r, which are padded with the r-bit IV, to obtain s bits, which are input
/// to the compression function. This function outputs r bits, which are used to chain to the
/// next iteration.
pub fn compress(message_block: [u8; S - R], iv_block: [u8; R]) -> [u8; OUTPUT_SIZE]  {
    // Start here
    let mut initial_vector = [0u8; R / 8];

    let w_indices = computing_W_indices(iv_block, message_block);
    for i in 0..W {
        let chosen_vec = w_indices[i] / R as u128;
        let shift_value = w_indices[i] % R as u128;
        let mut vector = define_iv(chosen_vec as usize);
        // shift the array
        shift_array(&mut vector, shift_value);
        // truncate array
        let mut truncated = [0u8; R / 8];
        truncated.copy_from_slice(&vector[..R / 8]);

        // Now we do the OR with the original vector
        initial_vector.iter_mut()
            .zip(truncated.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
    }

    // Now we use Whirpool
    let mut result = [0u8; OUTPUT_SIZE];
    let mut hasher = Whirlpool::new();
    // todo: careful here, with the bits out of bound
    hasher.update(str::from_utf8(&initial_vector).unwrap());
    result.copy_from_slice(&hasher.finalize()[..OUTPUT_SIZE]);
    result
}

// todo: we are always assuming that the bits are complete. This might not be the case everywhere
pub fn shift_array(array: &mut [u8; SIZE_VECTORS], shift_value: u128) {
    let byte_shift = shift_value / 8;
    let bit_shift = shift_value % 8;

    array.rotate_right(byte_shift as usize);
    // First we get the last bits, which will be the first bits. We expect that all but the first
    // P % 8 are 0.
    let last_bits = array.last().expect("Input array should be non-empty") << (8 - bit_shift as u8);

    // Now we shift the rest of the vector. This should work. Maybe not the most idiomatic, but
    // the logic seems correct.
    let mut xored_vector = last_bits;
    for index in 0..SIZE_VECTORS {
        let bit_vector = array[index];
        array[index] = xored_vector | (bit_vector >> bit_shift as u8);
        xored_vector = bit_vector << (8 - bit_shift as u8);
    }
}
