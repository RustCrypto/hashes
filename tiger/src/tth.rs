use crate::{Digest, Tiger, TigerCore};
use alloc::vec::Vec;
use core::fmt;
use digest::{
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::Unsigned,
    typenum::U1024,
    HashMarker, Output,
};

/// Core Tiger hasher state.
#[derive(Clone)]
pub struct TigerTreeCore {
    leaves: Vec<Output<TigerCore>>,
    hasher: Tiger,
    blocks_processed: usize,
}

impl Default for TigerTreeCore {
    fn default() -> Self {
        Self {
            leaves: Vec::default(),
            hasher: Tiger::new_with_prefix([LEAF_SIG]),
            blocks_processed: 0,
        }
    }
}

type DataBlockSize = U1024;
const LEAF_SIG: u8 = 0u8;
const NODE_SIG: u8 = 1u8;
/// The number of TigerCore blocks in a TigerTree data block
const LEAF_BLOCKS: usize = DataBlockSize::USIZE / <TigerCore as BlockSizeUser>::BlockSize::USIZE;

impl HashMarker for TigerTreeCore {}

impl BlockSizeUser for TigerTreeCore {
    type BlockSize = <TigerCore as BlockSizeUser>::BlockSize;
}

impl BufferKindUser for TigerTreeCore {
    type BufferKind = <TigerCore as BufferKindUser>::BufferKind;
}

impl OutputSizeUser for TigerTreeCore {
    type OutputSize = <TigerCore as OutputSizeUser>::OutputSize;
}

impl TigerTreeCore {
    #[inline]
    fn finalize_blocks(&mut self) {
        let hasher = core::mem::replace(&mut self.hasher, Tiger::new_with_prefix([LEAF_SIG]));
        let hash = hasher.finalize();
        self.leaves.push(hash);
        self.blocks_processed = 0;
    }

    #[inline]
    fn update_block(&mut self, block: Block<Self>) {
        self.hasher.update(block);
        self.blocks_processed += 1;
        if self.blocks_processed == LEAF_BLOCKS {
            self.finalize_blocks();
        }
    }
}

impl UpdateCore for TigerTreeCore {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        for block in blocks {
            self.update_block(*block);
        }
    }
}

impl FixedOutputCore for TigerTreeCore {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        if buffer.get_pos() > 0 {
            self.hasher.update(buffer.get_data());
            self.blocks_processed += 1;
        }

        if self.blocks_processed > 0 {
            self.finalize_blocks()
        }

        let result = hash_nodes(self.leaves.as_slice());
        out.copy_from_slice(&result);
    }
}

#[inline]
fn hash_nodes(hashes: &[Output<TigerCore>]) -> Output<TigerCore> {
    match hashes.len() {
        0 => hash_nodes(&[Tiger::digest([LEAF_SIG])]),
        1 => hashes[0],
        _ => {
            let left_hashes = hashes.iter().step_by(2);

            let right_hashes = hashes.iter().map(Some).skip(1).chain([None]).step_by(2);

            let next_level_hashes: Vec<Output<TigerCore>> = left_hashes
                .zip(right_hashes)
                .map(|(left, right)| match right {
                    Some(right) => Tiger::digest([&[NODE_SIG][..], left, right].concat()),
                    None => *left,
                })
                .collect();

            hash_nodes(next_level_hashes.as_slice())
        }
    }
}

impl Reset for TigerTreeCore {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for TigerTreeCore {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TigerTree")
    }
}

impl fmt::Debug for TigerTreeCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TigerTreeCore { ... }")
    }
}
