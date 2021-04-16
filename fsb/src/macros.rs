macro_rules! fsb_impl {
    (
        $state:ident, $state_num:expr, $blocksize:ident, $outputsize:ident, $n:expr, $w:expr,
        $r:expr, $p:expr, $s:expr
    ) => {
        use digest::consts::{$outputsize, $blocksize};
        // constants
        const N: usize = $n;
        const W: usize = $w;
        const R: usize = $r;
        const P: usize = $p;
        const S: usize = $s;

        const SIZE_OUTPUT_COMPRESS: usize = R / 8;
        const SIZE_INPUT_COMPRESS: usize = S / 8;
        const HASH_OUTPUT_SIZE: usize = $state_num / 8;
        const SIZE_MSG_CHUNKS: usize = SIZE_INPUT_COMPRESS - SIZE_OUTPUT_COMPRESS;
        const SIZE_VECTORS: usize = P / 8 + 1;
        const SHIFT: u8 = 8 - (P % 8) as u8;

        type BlockSize = $blocksize;
        type OutputSize = $outputsize;
        #[derive(Clone)]
        pub struct $state {
            /// bit size of the message till the current moment (the bit size is represented by a 64 bit
            /// number)
            bit_length: u64,
            /// size of the message being processed
            buffer: BlockBuffer<BlockSize>,
            /// value of the input vector
            hash: [u8; SIZE_OUTPUT_COMPRESS],
        }

        impl $state {
            fn update_len(&mut self, len: u64) {
                self.bit_length += len * 8;
            }

            fn finalize_inner(&mut self) {
                let hash = &mut self.hash;
                let pos = self.buffer.position();
                if pos < SIZE_MSG_CHUNKS - 8 {
                    let mut padding = vec![0; SIZE_MSG_CHUNKS - pos - 8];
                    padding[0] = 128u8;
                    padding.extend_from_slice(&helper_transform_usize(self.bit_length));
                    self.buffer
                        .input_block(&padding, |b| compress(hash, convert(b)));
                } else {
                    let mut padding = vec![0; SIZE_MSG_CHUNKS - pos];
                    padding[0] = 128u8;
                    self.buffer
                        .input_block(&padding, |b| compress(hash, convert(b)));
                    let mut second_padding = vec![0; SIZE_MSG_CHUNKS - 8];
                    second_padding.extend_from_slice(&helper_transform_usize(self.bit_length));
                    self.buffer
                        .input_block(&second_padding, |b| compress(hash, convert(b)));
                }
            }
        }

        // I'm trying to avoid use unsafe code for this transformation. We are certain that the size of the
        // buffer can be represented in 8 bytes.
        fn helper_transform_usize(x: u64) -> [u8; 8] {
            let b1: u8 = ((x >> 56) & 0xff) as u8;
            let b2: u8 = ((x >> 48) & 0xff) as u8;
            let b3: u8 = ((x >> 40) & 0xff) as u8;
            let b4: u8 = ((x >> 32) & 0xff) as u8;
            let b5: u8 = ((x >> 24) & 0xff) as u8;
            let b6: u8 = ((x >> 16) & 0xff) as u8;
            let b7: u8 = ((x >> 8) & 0xff) as u8;
            let b8: u8 = (x & 0xff) as u8;
            [b1, b2, b3, b4, b5, b6, b7, b8]
        }

        fn convert(block: &GenericArray<u8, $blocksize>) -> &[u8; SIZE_MSG_CHUNKS] {
            #[allow(unsafe_code)]
                unsafe {
                &*(block.as_ptr() as *const [u8; SIZE_MSG_CHUNKS])
            }
        }

        impl Default for $state {
            fn default() -> Self {
                Self {
                    bit_length: 0u64,
                    buffer: BlockBuffer::default(),
                    hash: [0u8; SIZE_OUTPUT_COMPRESS],
                }
            }
        }

        impl BlockInput for $state {
            type BlockSize = BlockSize;
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                let input = input.as_ref();
                self.update_len(input.len() as u64);

                let hash = &mut self.hash;
                self.buffer
                    .input_block(input, |b| compress(hash, convert(b)));
            }
        }

        impl FixedOutputDirty for $state {
            type OutputSize = OutputSize;

            fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, OutputSize>) {
                self.finalize_inner();
                let final_whirpool = final_compression(self.hash);
                out.copy_from_slice(&final_whirpool)
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.buffer.reset();
                for v in self.hash.iter_mut() {
                    *v = 0;
                }
            }
        }

        digest::impl_write!($state);

        pub fn define_iv(index: usize) -> [u8; SIZE_VECTORS] {
            // Now we take SIZE_VECTORS times b = n / r entries of Pi. In this way we'll have b vectors of p bits
            let mut subset_pi: [u8; SIZE_VECTORS] = [0u8; SIZE_VECTORS];
            subset_pi.copy_from_slice(&PI[index * SIZE_VECTORS..(index + 1) * SIZE_VECTORS]);

            // Now we change the last byte of the vector. We shift right and left, basically to
            // replace the last `shift` bits by zero. This is what I found to be most optimal.
            if let Some(last) = subset_pi.last_mut() {
                *last >>= SHIFT;
                *last <<= SHIFT;
            }

            subset_pi
        }

        /// Vector XORing. Given the s input bits of the function, we derive a set of w indexes
        /// $(W_i)_{i\in[0;w-1]}$ between $0$ and $n - 1$. The value of each $W_i$ is computed
        /// from the inputs bits like this:
        /// $W_i = i \times (n / w) + IV_i + M_i \times 2^{r / w}.
        fn computing_W_indices(
            input_vector: &[u8; SIZE_OUTPUT_COMPRESS],
            message: &[u8; SIZE_MSG_CHUNKS],
        ) -> [u32; W] {
            let mut W_indices: [u32; W] = [0; W];
            let divided_message: [u8; W] = dividing_bits(message, (S - R) / W);
            for i in 0..(W) {
                let message_i = divided_message[i] as u32;

                W_indices[i] = (i * N / W) as u32 + input_vector[i] as u32 + (message_i << (R / W) as u8);
            }

            W_indices
        }

        /// This function servers the purpose presented in table 3, of breaking a bit array into
        /// batches of size not multiple of 8. Note that the IV will be broken always in size 8, which
        /// is quite convenient. Also, the only numbers we'll have to worry for are 5 and 6.
        fn dividing_bits(input_bits: &[u8; SIZE_MSG_CHUNKS], size_batches: usize) -> [u8; W] {
            if size_batches != 5usize && size_batches != 6usize {
                panic!(
                    "Expecting batches of size 5 or 6. Other values do not follow \
                the standard specification"
                )
            }

            let mut new_bits = [0u8; W];
            let shifting_factor = (8 - size_batches) as u8;
            for (i, new_bit) in new_bits.iter_mut().enumerate().take(W - 1) {
                let position = i * size_batches;
                let initial_byte = position / 8;
                let initial_bit = position % 8;
                let switch = (initial_bit + size_batches - 1) / 8; // check if we use the next byte

                if switch == 1 {
                    *new_bit = (input_bits[initial_byte] << initial_bit as u8
                        | input_bits[initial_byte + 1] >> (8 - initial_bit as u8))
                        >> shifting_factor;
                } else {
                    *new_bit = (input_bits[initial_byte] << initial_bit as u8) >> shifting_factor;
                }
            }
            new_bits[W - 1] = (input_bits[SIZE_MSG_CHUNKS - 1] << 2) >> 2;

            new_bits
        }

        /// Blocks of size s - r, which are padded with the r-bit IV, to obtain s bits, which are input
        /// to the compression function. This function outputs r bits, which are used to chain to the
        /// next iteration.
        pub fn compress(hash: &mut [u8; SIZE_OUTPUT_COMPRESS], message_block: &[u8; SIZE_MSG_CHUNKS]) {
            let mut initial_vector = [0u8; SIZE_OUTPUT_COMPRESS];

            let w_indices = computing_W_indices(hash, message_block);
            for w_index in w_indices.iter() {
                let chosen_vec = w_index / R as u32;
                let shift_value = w_index % R as u32;
                let mut vector = define_iv(chosen_vec as usize);
                // shift and truncate the array
                let truncated = shift_and_truncate(&mut vector, shift_value);

                // Now we do the XOR with all vectors
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

            Update::update(&mut hasher, &initial_vector);
            result.copy_from_slice(&hasher.finalize()[..HASH_OUTPUT_SIZE]);
            result
        }

        pub fn shift_and_truncate(
            array: &mut [u8; SIZE_VECTORS],
            shift_value: u32,
        ) -> [u8; SIZE_OUTPUT_COMPRESS] {
            let array_len = array.len();
            let bits_in_cue = (P % 8) as u8;
            let mut truncated = [0u8; SIZE_OUTPUT_COMPRESS];

            if shift_value == 0 {
                array[..SIZE_OUTPUT_COMPRESS]
                    .try_into()
                    .expect("SIZE_VECTORS is always bigger than SIZE_OUTPUT_COMPRESS")
            } else if shift_value <= (bits_in_cue as u32) {
                let bytes_to_shift = 1;
                let starting_byte = (array_len - bytes_to_shift) as usize;

                truncated[0] = array[starting_byte] << (bits_in_cue - shift_value as u8);
                truncated[0] ^= array[0] >> shift_value;
                for position in 1..SIZE_OUTPUT_COMPRESS {
                    truncated[position] ^= array[position - 1] >> (8 - shift_value);
                    truncated[position] ^= array[position] << shift_value;
                }

                truncated
            } else {
                // First we need to decide which is the last byte and bit that will go to the first position.
                // Then, we build our truncated array from there. Recall that the last byte is not complete,
                // and we have a total of P % 8 hanging bits (this will always happen).
                let bytes_to_shift = (((shift_value - bits_in_cue as u32 - 1) / 8) + 2) as usize;
                // So then, the starting byte will be:
                let starting_byte = (array_len - bytes_to_shift) as usize;

                // paraphrasing, the ceil (of the total shift, minus the remaining bits divided by 8) plus one.
                // Which is equivalent to the floor (of the total shift, minus the remaining bits divided by 8)
                // plus two.
                // And the starting bit:
                let remaining_bits = ((shift_value - bits_in_cue as u32) % 8) as u8;

                if remaining_bits != 0 {
                    for position in 0..(bytes_to_shift - 1) {
                        truncated[position] = array[starting_byte + position] << (8 - remaining_bits)
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
                                truncated[bytes_to_shift - 1] ^=
                                    array[starting_byte + bytes_to_shift - 1] << (bits_in_cue - x);
                                truncated[bytes_to_shift - 1] ^= array[0] >> x;
                                for (index, position) in (bytes_to_shift..SIZE_OUTPUT_COMPRESS).enumerate()
                                {
                                    truncated[position] ^= array[index] << (8 - x);
                                    truncated[position] ^= array[index + 1] >> x;
                                }
                            } else {
                                for (index, position) in
                                    ((bytes_to_shift - 1)..SIZE_OUTPUT_COMPRESS).enumerate()
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
                                ((bytes_to_shift - 1)..SIZE_OUTPUT_COMPRESS).enumerate()
                            {
                                truncated[position] ^= array[index] << positive_diff;
                                truncated[position] ^= array[index + 1] >> (8 - positive_diff);
                            }
                        }
                    }

                    truncated
                } else {
                    truncated[..bytes_to_shift]
                        .clone_from_slice(&array[starting_byte..(starting_byte + bytes_to_shift)]);

                    // we need to fill the remainder with bits of the next byte.
                    truncated[bytes_to_shift - 1] ^= array[0] >> bits_in_cue;
                    for (index, position) in (bytes_to_shift..SIZE_OUTPUT_COMPRESS).enumerate() {
                        truncated[position] ^= array[index] << (8 - bits_in_cue);
                        truncated[position] ^= array[index + 1] >> bits_in_cue;
                    }
                    truncated
                }
            }
        }
    }
}