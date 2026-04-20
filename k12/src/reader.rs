use crate::consts::ROUNDS;
use core::fmt;
use digest::{
    XofReader,
    block_buffer::{BlockSizes, ReadBuffer},
};
use keccak::{Keccak, State1600};

/// KangarooTwelve XOF reader generic over rate.
#[derive(Clone)]
pub struct KtReader<Rate: BlockSizes> {
    pub(crate) state: State1600,
    pub(crate) buffer: ReadBuffer<Rate>,
    pub(crate) keccak: Keccak,
}

impl<Rate: BlockSizes> XofReader for KtReader<Rate> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) {
        let Self {
            state,
            buffer,
            keccak,
        } = self;

        buffer.read(buf, |block| {
            let mut chunks = block.chunks_exact_mut(8);
            for (src, dst) in state.iter().zip(&mut chunks) {
                dst.copy_from_slice(&src.to_le_bytes());
            }
            assert!(
                chunks.into_remainder().is_empty(),
                "rate is either 136 or 168",
            );
            keccak.with_p1600::<ROUNDS>(|p1600| p1600(state));
        });
    }
}

impl<Rate: BlockSizes> fmt::Debug for KtReader<Rate> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let debug_str = match Rate::USIZE {
            168 => "Kt128Reader { ... }",
            136 => "Kt256Reader { ... }",
            _ => unreachable!(),
        };
        f.write_str(debug_str)
    }
}

impl<Rate: BlockSizes> Drop for KtReader<Rate> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            use digest::zeroize::Zeroize;
            self.state.zeroize();
            // self.buffer is zeroized by its `Drop`
        }
    }
}

#[cfg(feature = "zeroize")]
impl<Rate: BlockSizes> digest::zeroize::ZeroizeOnDrop for KtReader<Rate> {}
