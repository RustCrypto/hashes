macro_rules! fsb_impl {
    (
        $full_state:ident, $state:ident, $state_num:expr, $blocksize:ident, $outputsize:ident, $n:expr, $w:expr,
        $r:expr, $p:expr, $s:expr, $full_doc:expr, $doc:expr,
    ) => {
        use digest::consts::{$blocksize, $outputsize};

        #[derive(Clone)]
        #[doc=$doc]
        pub struct $state {
            blocks_len: u64,
            state: [u8; $r / 8],
        }

        impl HashMarker for $state {}

        impl BlockSizeUser for $state {
            type BlockSize = $blocksize;
        }

        impl OutputSizeUser for $state {
            type OutputSize = $outputsize;
        }

        impl BufferKindUser for $state {
            type BufferKind = Eager;
        }

        impl UpdateCore for $state {
            #[inline]
            fn update_blocks(&mut self, blocks: &[Block<Self>]) {
                self.blocks_len += blocks.len() as u64;
                for block in blocks {
                    Self::compress(&mut self.state, Self::convert(block));
                }
            }
        }

        impl FixedOutputCore for $state {
            #[inline]
            fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
                let block_bytes = self.blocks_len * Self::BlockSize::U64;
                let bit_len = 8 * (block_bytes + buffer.get_pos() as u64);
                let mut h = self.state;
                buffer.len64_padding_be(bit_len, |b| Self::compress(&mut h, Self::convert(b)));

                let res = whirlpool::Whirlpool::digest(&h[..]);
                let n = out.len();
                out.copy_from_slice(&res[..n]);
            }
        }

        impl Default for $state {
            #[inline]
            fn default() -> Self {
                Self {
                    blocks_len: 0u64,
                    state: [0u8; $r / 8],
                }
            }
        }

        impl Reset for $state {
            #[inline]
            fn reset(&mut self) {
                *self = Default::default();
            }
        }

        impl AlgorithmName for $state {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($full_state))
            }
        }

        impl fmt::Debug for $state {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($state), " { ... }"))
            }
        }

        #[doc=$full_doc]
        pub type $full_state = CoreWrapper<$state>;

        impl $state {
            const SIZE_OUTPUT_COMPRESS: usize = $r / 8;
            const SIZE_INPUT_COMPRESS: usize = $s / 8;
            const SIZE_MSG_CHUNKS: usize = Self::SIZE_INPUT_COMPRESS - Self::SIZE_OUTPUT_COMPRESS;
            const SIZE_VECTORS: usize = $p / 8 + 1;
            const SHIFT: u8 = 8 - ($p % 8) as u8;

            fn define_iv(index: usize) -> [u8; Self::SIZE_VECTORS] {
                let mut subset_pi: [u8; Self::SIZE_VECTORS] = [0u8; Self::SIZE_VECTORS];
                subset_pi.copy_from_slice(
                    &PI[index * Self::SIZE_VECTORS..(index + 1) * Self::SIZE_VECTORS],
                );

                // Now we change the last byte of the vector. We shift right and left, basically to
                // replace the last `shift` bits by zero.
                if let Some(last) = subset_pi.last_mut() {
                    *last >>= Self::SHIFT;
                    *last <<= Self::SHIFT;
                }

                subset_pi
            }

            /// Vector XORing. Given the s input bits of the function, we derive a set of w indexes
            /// $(W_i)_{i\in[0;w-1]}$ between $0$ and $n - 1$. The value of each $W_i$ is computed
            /// from the inputs bits like this:
            /// $W_i = i \times (n / w) + IV_i + M_i \times 2^{r / w}.
            fn computing_w_indices(
                input_vector: &[u8; Self::SIZE_OUTPUT_COMPRESS],
                message: &[u8; Self::SIZE_MSG_CHUNKS],
            ) -> [u32; $w] {
                let mut wind: [u32; $w] = [0; $w];
                let divided_message: [u8; $w] = Self::dividing_bits(message, ($s - $r) / $w);
                for i in 0..($w) {
                    let message_i = divided_message[i] as u32;

                    wind[i] = (i * $n / $w) as u32
                        + input_vector[i] as u32
                        + (message_i << ($r / $w) as u8);
                }

                wind
            }

            /// This function servers the purpose presented in table 3, of breaking a bit array into
            /// batches of size not multiple of 8. Note that the IV will be broken always in size 8, which
            /// is quite convenient. Also, the only numbers we'll have to worry for are 5 and 6.
            fn dividing_bits(
                input_bits: &[u8; Self::SIZE_MSG_CHUNKS],
                size_batches: usize,
            ) -> [u8; $w] {
                if size_batches != 5usize && size_batches != 6usize {
                    panic!(
                        "Expecting batches of size 5 or 6. Other values do not follow \
                    the standard specification"
                    )
                }

                let mut new_bits = [0u8; $w];
                let shifting_factor = (8 - size_batches) as u8;
                for (i, new_bit) in new_bits.iter_mut().enumerate().take($w - 1) {
                    let position = i * size_batches;
                    let initial_byte = position / 8;
                    let initial_bit = position % 8;
                    let switch = (initial_bit + size_batches - 1) / 8; // check if we use the next byte

                    if switch == 1 {
                        *new_bit = (input_bits[initial_byte] << initial_bit as u8
                            | input_bits[initial_byte + 1] >> (8 - initial_bit as u8))
                            >> shifting_factor;
                    } else {
                        *new_bit =
                            (input_bits[initial_byte] << initial_bit as u8) >> shifting_factor;
                    }
                }
                new_bits[$w - 1] =
                    (input_bits[Self::SIZE_MSG_CHUNKS - 1] << shifting_factor) >> shifting_factor;

                new_bits
            }

            /// This function outputs r bits, which are used to chain to the next iteration.
            fn compress(
                hash: &mut [u8; Self::SIZE_OUTPUT_COMPRESS],
                message_block: &[u8; Self::SIZE_MSG_CHUNKS],
            ) {
                let mut initial_vector = [0u8; Self::SIZE_OUTPUT_COMPRESS];

                let w_indices = Self::computing_w_indices(hash, message_block);
                for w_index in w_indices.iter() {
                    let chosen_vec = w_index / $r as u32;
                    let shift_value = w_index % $r as u32;
                    let mut vector = Self::define_iv(chosen_vec as usize);
                    let truncated = Self::shift_and_truncate(&mut vector, shift_value);

                    initial_vector
                        .iter_mut()
                        .zip(truncated.iter())
                        .for_each(|(x1, x2)| *x1 ^= *x2);
                }

                *hash = initial_vector;
            }

            fn shift_and_truncate(
                array: &mut [u8; Self::SIZE_VECTORS],
                shift_value: u32,
            ) -> [u8; Self::SIZE_OUTPUT_COMPRESS] {
                let array_len = array.len();
                let bits_in_cue = ($p % 8) as u8;
                let mut truncated = [0u8; Self::SIZE_OUTPUT_COMPRESS];

                if shift_value == 0 {
                    truncated.copy_from_slice(&array[..Self::SIZE_OUTPUT_COMPRESS]);
                } else if shift_value <= (bits_in_cue as u32) {
                    let bytes_to_shift = 1;
                    let starting_byte = (array_len - bytes_to_shift) as usize;

                    truncated[0] = array[starting_byte] << (bits_in_cue - shift_value as u8);
                    truncated[0] ^= array[0] >> shift_value;
                    for position in 1..Self::SIZE_OUTPUT_COMPRESS {
                        truncated[position] ^= array[position - 1] >> (8 - shift_value);
                        truncated[position] ^= array[position] << shift_value;
                    }
                } else {
                    // First we need to decide which is the last byte and bit that will go to the first position.
                    // Then, we build our truncated array from there. Recall that the last byte is not complete,
                    // and we have a total of P % 8 hanging bits (this will always happen).
                    let bytes_to_shift =
                        (((shift_value - bits_in_cue as u32 - 1) / 8) + 2) as usize;
                    // So then, the starting byte will be:
                    let starting_byte = (array_len - bytes_to_shift) as usize;

                    // And the starting bit:
                    let remaining_bits = ((shift_value - bits_in_cue as u32) % 8) as u8;

                    if remaining_bits != 0 {
                        for position in 0..(bytes_to_shift - 1) {
                            truncated[position] = array[starting_byte + position]
                                << (8 - remaining_bits)
                                | array[starting_byte + position + 1] >> remaining_bits;
                        }

                        // The last case is different, as we don't know if there are sufficient bits in the cue to fill
                        // up a full byte. We have three cases: 1. where P % 8 (bits_in_cue) is larger than
                        // starting_bit, 2. where it is equal, and 3. where it is smaller. But we can fill the bits, and
                        // then decide how to proceed depending on the difference.
                        let difference = bits_in_cue.checked_sub(8 - remaining_bits);

                        match difference {
                            Some(x) => {
                                if x > 0 {
                                    // the next position takes starting_bits from the byte with the remaining zeros, and
                                    // `difference` from the first byte. Then we iterate by shifting 8 - difference bits.
                                    truncated[bytes_to_shift - 1] ^= array
                                        [starting_byte + bytes_to_shift - 1]
                                        << (bits_in_cue - x);
                                    truncated[bytes_to_shift - 1] ^= array[0] >> x;
                                    for (index, position) in
                                        (bytes_to_shift..Self::SIZE_OUTPUT_COMPRESS).enumerate()
                                    {
                                        truncated[position] ^= array[index] << (8 - x);
                                        truncated[position] ^= array[index + 1] >> x;
                                    }
                                } else {
                                    for (index, position) in ((bytes_to_shift - 1)
                                        ..Self::SIZE_OUTPUT_COMPRESS)
                                        .enumerate()
                                    {
                                        truncated[position] = array[index];
                                    }
                                }
                            }
                            None => {
                                let positive_diff = (8 - remaining_bits) - bits_in_cue;
                                // we need to fill the remainder with bits of the next byte.
                                truncated[bytes_to_shift - 2] ^= array[0] >> (8 - positive_diff);
                                for (index, position) in
                                    ((bytes_to_shift - 1)..Self::SIZE_OUTPUT_COMPRESS).enumerate()
                                {
                                    truncated[position] ^= array[index] << positive_diff;
                                    truncated[position] ^= array[index + 1] >> (8 - positive_diff);
                                }
                            }
                        }
                    } else {
                        truncated[..bytes_to_shift].clone_from_slice(
                            &array[starting_byte..(starting_byte + bytes_to_shift)],
                        );

                        // we need to fill the remainder with bits of the next byte.
                        truncated[bytes_to_shift - 1] ^= array[0] >> bits_in_cue;
                        for (index, position) in
                            (bytes_to_shift..Self::SIZE_OUTPUT_COMPRESS).enumerate()
                        {
                            truncated[position] ^= array[index] << (8 - bits_in_cue);
                            truncated[position] ^= array[index + 1] >> bits_in_cue;
                        }
                    }
                }
                truncated
            }

            fn convert(block: &GenericArray<u8, $blocksize>) -> &[u8; Self::SIZE_MSG_CHUNKS] {
                unsafe { &*(block.as_ptr() as *const [u8; Self::SIZE_MSG_CHUNKS]) }
            }
        }
    };
}
