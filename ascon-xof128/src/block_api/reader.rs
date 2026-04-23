use ascon::State;
use digest::{
    block_api::{Block, BlockSizeUser, XofReaderCore},
    consts::U8,
};

/// Ascon-XOF128 block-level reader
#[derive(Clone, Debug)]
pub struct AsconXofReaderCore {
    pub(super) state: State,
}

impl BlockSizeUser for AsconXofReaderCore {
    type BlockSize = U8;
}

impl XofReaderCore for AsconXofReaderCore {
    fn read_block(&mut self) -> Block<Self> {
        ascon::permute12(&mut self.state);
        self.state[0].to_le_bytes().into()
    }
}
