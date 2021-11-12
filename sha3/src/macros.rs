macro_rules! impl_state {
    ($state:ident, $rate:ident, $padding:ty, $doc:expr) => {
        #[allow(non_camel_case_types)]
        #[derive(Clone, Default)]
        #[doc=$doc]
        pub struct $state {
            state: Sha3State,
            buffer: BlockBuffer<$rate>,
        }

        impl $state {
            fn absorb(&mut self, input: &[u8]) {
                let s = &mut self.state;
                self.buffer.input_block(input, |b| s.absorb_block(b));
            }

            fn apply_padding(&mut self) {
                let buf = self
                    .buffer
                    .pad_with::<$padding>()
                    .expect("we never use input_lazy");
                self.state.absorb_block(buf);
            }
        }
    };
}

macro_rules! sha3_impl {
    ($state:ident, $output_size:ident, $rate:ident, $padding:ty, $doc:expr) => {
        impl_state!($state, $rate, $padding, $doc);

        impl BlockInput for $state {
            type BlockSize = $rate;
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                self.absorb(input.as_ref())
            }
        }

        impl FixedOutputDirty for $state {
            type OutputSize = $output_size;

            fn finalize_into_dirty(&mut self, out: &mut digest::Output<Self>) {
                self.apply_padding();

                let n = out.len();
                self.state.as_bytes(|state| {
                    out.copy_from_slice(&state[..n]);
                });
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.state = Default::default();
                self.buffer.reset();
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}

macro_rules! shake_impl {
    ($state:ident, $rate:ident, $padding:ty, $doc:expr) => {
        impl_state!($state, $rate, $padding, $doc);

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                self.absorb(input.as_ref())
            }
        }

        impl ExtendableOutputDirty for $state {
            type Reader = Sha3XofReader;

            fn finalize_xof_dirty(&mut self) -> Sha3XofReader {
                self.apply_padding();
                let r = $rate::to_usize();
                Sha3XofReader::new(self.state.clone(), r)
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.state = Default::default();
                self.buffer.reset();
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}

macro_rules! cshake_impl {
    ($state:ident, $rate:ident, $doc:expr) => {
        #[allow(non_camel_case_types)]
        #[derive(Clone)]
        #[doc=$doc]
        pub struct $state {
            init_state: Sha3State,
            state: Sha3State,
            buffer: BlockBuffer<$rate>,
            has_customization: bool,
        }

        impl $state {
            /// Create a new hasher instance using a customization string
            /// The customization string is used as domain separation to separate different instances of the same hash function
            pub fn new(customization_string: &[u8]) -> Self {
                use $crate::left_encode;
                let mut buffer = BlockBuffer::default();
                let mut state = Sha3State::default();
                if customization_string.is_empty() {
                    return Self {
                        init_state: state.clone(),
                        state,
                        buffer,
                        has_customization: false,
                    };
                }

                let mut array_buf = [0u8; 9];
                buffer.input_block(left_encode($rate::to_u64(), &mut array_buf), |b| {
                    state.absorb_block(b)
                });

                // This is the encoding of `left_encode(0)`
                let empty_function_name = [1, 0];
                buffer.input_block(&empty_function_name, |b| state.absorb_block(b));
                // buffer.input_block(left_encode((N.len() * 8) as u64, &mut array_buf), |b| {
                //     state.absorb_block(b)
                // });
                // buffer.input_block(N, |b| state.absorb_block(b));
                buffer.input_block(
                    left_encode((customization_string.len() * 8) as u64, &mut array_buf),
                    |b| state.absorb_block(b),
                );
                buffer.input_block(customization_string, |b| state.absorb_block(b));

                state.absorb_block(
                    buffer
                        .pad_with::<ZeroPadding>()
                        .expect("ZeroPadding should never fail"),
                );

                Self {
                    init_state: state.clone(),
                    state,
                    buffer,
                    has_customization: true,
                }
            }
            fn absorb(&mut self, input: &[u8]) {
                let s = &mut self.state;
                self.buffer.input_block(input, |b| s.absorb_block(b));
            }

            fn apply_padding(&mut self) {
                let buf = if self.has_customization {
                    self.buffer
                        .pad_with::<CShake>()
                        .expect("we never use input_lazy")
                } else {
                    self.buffer
                        .pad_with::<Shake>()
                        .expect("we never use input_lazy")
                };
                self.state.absorb_block(buf);
            }
        }

        impl Update for $state {
            fn update(&mut self, input: impl AsRef<[u8]>) {
                self.absorb(input.as_ref())
            }
        }

        impl ExtendableOutputDirty for $state {
            type Reader = Sha3XofReader;

            fn finalize_xof_dirty(&mut self) -> Sha3XofReader {
                self.apply_padding();
                let r = $rate::to_usize();
                Sha3XofReader::new(self.state.clone(), r)
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.state = self.init_state.clone();
                self.buffer.reset();
            }
        }

        opaque_debug::implement!($state);
        digest::impl_write!($state);
    };
}
