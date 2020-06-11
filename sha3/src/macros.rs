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
                let buf = self.buffer.pad_with::<$padding>()
                    .expect("we never use input_lazy");
                self.state.absorb_block(buf);
            }
        }
    }
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
