macro_rules! sha3_impl {
    ($state:ident, $output_size:ident, $rate:ty, $padding:ty) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone, Default)]
        pub struct $state {
            engine: Sha3<$rate, $padding>,
        }

        impl digest::BlockInput for $state {
            type BlockSize = $rate;
        }

        impl digest::Input for $state {
            fn process(&mut self, data: &[u8]) {
                self.engine.absorb(data)
            }
        }

        impl digest::FixedOutput for $state {
            type OutputSize = $output_size;

            fn fixed_result(mut self) -> GenericArray<u8, Self::OutputSize> {
                let mut out = GenericArray::default();
                self.engine.apply_padding();
                self.engine.readout(out.as_mut_slice());
                out
            }
        }

    }
}

macro_rules! shake_impl {
    ($state:ident, $rate:ty, $padding:ty) => {
        #[derive(Copy, Clone, Default)]
        pub struct $state {
            engine: Sha3<$rate, $padding>,
        }

        impl digest::Input for $state {
            fn process(&mut self, data: &[u8]) {
                self.engine.absorb(data)
            }
        }

        impl digest::ExtendableOutput for $state {
            type Reader = Sha3XofReader;

            fn xof_result(mut self) -> Sha3XofReader
            {
                self.engine.apply_padding();
                Sha3XofReader::new(self.engine.state, self.engine.rate())
            }
        }

    }
}
