macro_rules! sha3_impl {
    ($state:ident, $output_size:ident, $rate:ident, $padding:expr) => {
        #[allow(non_camel_case_types)]
        #[derive(Copy, Clone)]
        pub struct $state {
            engine: Sha3,
        }

        impl Default for $state {
            fn default() -> Self {
                $state {engine: Sha3::new($rate::to_usize(), $padding)}
            }
        }

        impl digest::Input for $state {
            type BlockSize = $rate;

            fn digest(&mut self, data: &[u8]) {
                self.engine.absorb(data)
            }
        }

        impl digest::FixedOutput for $state {
            type OutputSize = $output_size;

            fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
                let mut out = GenericArray::default();
                self.engine.finish(&mut out);
                out
            }
        }

    }
}

macro_rules! shake_impl {
    ($state:ident, $rate:ident, $padding:expr) => {
        #[derive(Copy, Clone)]
        pub struct $state {
            engine: Sha3,
        }

        impl Default for $state {
            fn default() -> Self {
                $state {engine: Sha3::new($rate::to_usize(), $padding)}
            }
        }

        impl digest::Input for $state {
            type BlockSize = $rate;

            fn digest(&mut self, data: &[u8]) {
                self.engine.absorb(data)
            }
        }


        impl digest::VariableOutput for $state {
            fn variable_result(self, buffer: &mut [u8])
                    -> digest::VariableResult
            {
                if buffer.len() != 0 {
                    self.engine.finish(buffer);
                    Ok(buffer)
                } else {
                    Err(digest::InvalidLength)
                }
            }
        }

    }
}
