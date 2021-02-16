use core::fmt;
use digest::{
    block_buffer::BlockBuffer,
    core_api::{AlgorithmName, CoreWrapper, FixedOutputCore, UpdateCore},
    generic_array::{typenum::U64, GenericArray},
    Reset,
};

use crate::streebog::StreebogState;

/// Core Streebog512 hasher state.
#[derive(Clone)]
pub struct Streebog512Core {
    state: StreebogState,
}

impl UpdateCore for Streebog512Core {
    type BlockSize = U64;
    type Buffer = BlockBuffer<U64>;

    #[inline]
    fn update_blocks(&mut self, blocks: &[GenericArray<u8, Self::BlockSize>]) {
        self.state.update_blocks(blocks);
    }
}

impl FixedOutputCore for Streebog512Core {
    type OutputSize = U64;

    #[inline]
    fn finalize_fixed_core(
        &mut self,
        buffer: &mut BlockBuffer<Self::BlockSize>,
        out: &mut GenericArray<u8, Self::OutputSize>,
    ) {
        self.state.finalize(buffer);
        out.copy_from_slice(&self.state.h)
    }
}

impl Default for Streebog512Core {
    #[inline]
    fn default() -> Self {
        let state = StreebogState {
            h: [0u8; 64],
            n: Default::default(),
            sigma: Default::default(),
        };
        Self { state }
    }
}

impl Reset for Streebog512Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for Streebog512Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog512")
    }
}

impl fmt::Debug for Streebog512Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Streebog512Core { ... }")
    }
}

/// Streebog512 hasher state.
pub type Streebog512 = CoreWrapper<Streebog512Core>;
