use digest::generic_array::typenum::{U128, U64};

blake2_impl!(
    VarBlake2b,
    Blake2b,
    blake2b_simd::State,
    blake2b_simd::Params,
    U128,
    U64,
    U64,
    "Blake2b instance with a variable output.",
    "Blake2b instance with a fixed output.",
);

impl VarBlake2b {
    /// Creates a new hashing context with the full set of sequential-mode parameters.
    pub fn with_params(key: &[u8], salt: &[u8], persona: &[u8], output_size: usize) -> Self {
        let mut upstream_params = blake2b_simd::Params::new();
        upstream_params
            .key(key)
            .salt(salt)
            .personal(persona)
            .hash_length(output_size);
        let upstream_state = upstream_params.to_state();
        Self {
            upstream_params,
            upstream_state,
            output_size,
        }
    }
}

impl Blake2b {
    /// Creates a new hashing context with the full set of sequential-mode parameters.
    pub fn with_params(key: &[u8], salt: &[u8], persona: &[u8]) -> Self {
        let mut upstream_params = blake2b_simd::Params::new();
        upstream_params.key(key).salt(salt).personal(persona);
        let upstream_state = upstream_params.to_state();
        Self {
            upstream_params,
            upstream_state,
        }
    }
}
