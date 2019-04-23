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
                let self_state = &mut self.state;
                self.buffer.input(input, |b| self_state.absorb_block(b));
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

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, input: B) {
                self.absorb(input.as_ref())
            }
        }

        impl FixedOutput for $state {
            type OutputSize = $output_size;

            fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
                self.apply_padding();

                let mut out = GenericArray::default();
                let n = out.len();
                self.state.as_bytes(|state| {
                    out.copy_from_slice(&state[..n]);
                });
                out
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.state = Default::default();
                self.buffer.reset();
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);
    }
}

macro_rules! shake_impl {
    ($state:ident, $rate:ident, $padding:ty, $doc:expr) => {
        impl_state!($state, $rate, $padding, $doc);

        impl Input for $state {
            fn input<B: AsRef<[u8]>>(&mut self, input: B) {
                self.absorb(input.as_ref())
            }
        }

        impl ExtendableOutput for $state {
            type Reader = Sha3XofReader;

            fn xof_result(mut self) -> Sha3XofReader {
                self.apply_padding();
                let r = $rate::to_usize();
                let res = Sha3XofReader::new(self.state.clone(), r);
                res
            }
        }

        impl Reset for $state {
            fn reset(&mut self) {
                self.state = Default::default();
                self.buffer.reset();
            }
        }

        impl_opaque_debug!($state);
        impl_write!($state);
    }
}
