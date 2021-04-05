#![allow(non_snake_case)]

use crate::pi::Pi;
use whirlpool::{Digest, Whirlpool};

use std::str;
use std::convert::TryInto;

const N: usize = 5 >> 18;
// number of indexes
const W: usize = 80;

pub(crate) const R: usize = 640;
pub const SIZE_OUTPUT_COMPRESS: usize = R / 8;
const P: usize = 653;
const S: usize = 1_120;
const SIZE_INPUT_COMPRESS: usize = S / 8; // s = w * log_2(n/w)

const HASH_OUTPUT_SIZE: usize = 160 / 8;

pub const SIZE_MSG_CHUNKS: usize = SIZE_INPUT_COMPRESS - SIZE_OUTPUT_COMPRESS;

// This is not declared as a variable of the algorithm, but I need it to be const to create
// arrays of this length. This represents the number of V vectors.
const NR_VECTORS: usize = N / R;

// Again, this is not declared as variable in the algorithm. For now let's keep it this way.
// Note that this is computing the ceiling (we now that P is not divisible by 8, never).
const SIZE_VECTORS: usize = P / 8 + 1;

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
fn computing_W_indices(
    input_vector: &[u8; SIZE_OUTPUT_COMPRESS],
    message: &[u8; SIZE_MSG_CHUNKS],
) -> [u128; W] {
    let mut W_indices: [u128; W] = [0; W];
    let divided_message: [u8; W] = dividing_bits(message, (S - R) / W);
    // todo: we are clearly delcaring unnecesary variables. For the moment keep for readability.
    for i in 0..(W) {
        let input_vector_i = input_vector[i]; // r/w is always 8, see table 3
        let message_i = divided_message[i] as u128;

        W_indices[i] = (i * N / W) as u128 + input_vector_i as u128 + (message_i << (R / W) as u8);
    }

    W_indices
}

/// This function servers the purpose presented in table 3, of breaking a bit array into
/// batches of size not multiple of 8. Note that the IV will be broken always in size 8, which
/// is quite convenient. Also, the only numbers we'll have to worry for are 5 and 6.
fn dividing_bits(input_bits: &[u8], size_batches: usize) -> [u8; W] {
    if size_batches != 5usize && size_batches != 6usize {
        panic!(
            "Expecting batches of size 5 or 6. Other values do not follow \
        the standard specification"
        )
    }

    let mut new_bits = [0u8; W];
    // should this be -1?
    let shifting_factor = (8 - size_batches) as u8;
    for i in 0..W {
        let position = i * size_batches;
        let initial_byte = position / 8;
        let initial_bit = position % 8;
        let switch = (initial_bit + size_batches - 1) / 8; // check if we use the next byte

        // Might be a better way to do this function
        if switch == 1 {
            new_bits[i] = (input_bits[initial_byte] << initial_bit as u8
                | input_bits[initial_byte + 1] >> (8 - initial_bit as u8))
                >> shifting_factor;
        } else {
            new_bits[i] = (input_bits[initial_byte] << initial_bit as u8) >> shifting_factor;
        }
    }

    new_bits
}

/// Blocks of size s - r, which are padded with the r-bit IV, to obtain s bits, which are input
/// to the compression function. This function outputs r bits, which are used to chain to the
/// next iteration.
pub fn compress(hash: &mut [u8; SIZE_OUTPUT_COMPRESS], message_block: &[u8; SIZE_MSG_CHUNKS]) {
    // Start here. todo: I'm not sure of this initialisation. But let's try to compile for now.
    let mut initial_vector = [0u8; SIZE_OUTPUT_COMPRESS];

    let w_indices = computing_W_indices(hash, message_block);
    for i in 0..W {
        let chosen_vec = w_indices[i] / R as u128;
        let shift_value = w_indices[i] % R as u128;
        let mut vector = define_iv(chosen_vec as usize);
        // shift and truncate the array
        let truncated = shift_and_truncate(&mut vector, shift_value);

        // Now we do the OR with all vectors
        initial_vector
            .iter_mut()
            .zip(truncated.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
    }

    *hash = initial_vector;
}

pub fn final_compression(initial_vector: [u8; SIZE_OUTPUT_COMPRESS]) -> [u8; HASH_OUTPUT_SIZE] {
    // Now we use Whirpool
    let mut result = [0u8; HASH_OUTPUT_SIZE];
    let mut hasher = Whirlpool::new();

    hasher.update(&initial_vector);
    result.copy_from_slice(&hasher.finalize()[..HASH_OUTPUT_SIZE]);
    result
}

pub fn shift_and_truncate(
    array: &mut [u8; SIZE_VECTORS],
    shift_value: u128,
) -> [u8; SIZE_OUTPUT_COMPRESS] {
    let array_len = array.len();
    let bits_in_cue = (P % 8) as u128;
    let mut truncated = [0u8; SIZE_OUTPUT_COMPRESS];

    // todo: we need to take care of other edge cases, when shift_value <= bits_in_cue
    if shift_value == 0 {
        return array[..SIZE_OUTPUT_COMPRESS].try_into().expect("SIZE_VECTORS is always bigger than SIZE_OUTPUT_COMPRESS");
    }

    // First we need to decide which is the last byte and bit that will go to the first position.
    // Then, we build our truncated array from there. Recall that the last byte is not complete,
    // and we have a total of P % 8 hanging bits (this will always happen).
    let bytes_to_shift = (((shift_value - bits_in_cue - 1) / 8) + 2) as usize;
    // So then, the starting byte will be:
    let starting_byte = (array_len - bytes_to_shift) as usize;

    // paraphrasing, the ceil (of the total shift, minus the remaining bits divided by 8) plus one.
    // Which is equivalent to the floor (of the total shift, minus the remaining bits divided by 8)
    // plus two.
    // And the starting bit:
    // todo: double check that shift_value is always larger than P.
    let starting_bit = 8 - ((shift_value - bits_in_cue) % 8);

    for position in 0..(bytes_to_shift - 2) {
        truncated[position] ^= array[starting_byte + position] << starting_bit;
        truncated[position] ^= array[starting_byte + position + 1] >> (8 - starting_bit);
    }

    // The last case is different, as we don't know if there are sufficient bits in the cue to fill
    // up a full byte. We have three cases: 1. where P % 8 (bits_in_cue) is larger than
    // starting_bit, 2. where it is equal, and 3. where it is smaller. But we can fill the bits, and
    // then decide how to proceed depending on the difference.
    let difference = bits_in_cue.checked_sub(starting_bit);

    truncated[bytes_to_shift - 2] ^= array[starting_byte + bytes_to_shift - 2] << starting_bit;
    truncated[bytes_to_shift - 2] ^=
        array[starting_byte + bytes_to_shift - 2 + 1] >> (8 - starting_bit);

    match difference {
        Some(x) => {
            if x > 0 {
                // the next position takes starting_bits from the byte with the remaining zeros, and
                // `difference` from the first byte. Then we iterate by shifting 8 - difference bits.
                truncated[bytes_to_shift - 1] ^= array[starting_byte + bytes_to_shift - 2] << starting_bit;
                truncated[bytes_to_shift - 1] ^= array[0] >> x;
                for (index, position) in (bytes_to_shift..SIZE_OUTPUT_COMPRESS).enumerate() {
                    truncated[position] ^= array[index] << (8 - x);
                    truncated[position] ^= array[index + 1] >> x;
                }
            }
            else {
                for (index, position) in ((bytes_to_shift - 1)..SIZE_OUTPUT_COMPRESS).enumerate() {
                    truncated[position] = array[index];
                }
            }

        },
        None => {
            let positive_diff = starting_bit - bits_in_cue;
            // we need to fill the remainder with bits of the next byte.
            truncated[bytes_to_shift - 2] ^= array[0] >> (8 - positive_diff);
            for (index, position) in ((bytes_to_shift - 1)..SIZE_OUTPUT_COMPRESS).enumerate() {
                truncated[position] ^= array[index] >> positive_diff;
                truncated[position] ^= array[index + 1] << (8 - positive_diff);
            }
        },

    }

    truncated
}
