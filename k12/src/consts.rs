/// Number of permutation rounds used by k12
pub(crate) const ROUNDS: usize = 12;
/// Chunk size used by k12
pub(crate) const CHUNK_SIZE: usize = 1 << 13;
pub(crate) const CHUNK_SIZE_U64: u64 = CHUNK_SIZE as u64;

pub(crate) const SINGLE_NODE_DS: u8 = 0x07;
pub(crate) const INTERMEDIATE_NODE_DS: u8 = 0x0B;
pub(crate) const FINAL_NODE_DS: u8 = 0x06;

pub(crate) const S0_DELIM: u64 = 0x03;
pub(crate) const PAD: u64 = 1 << 63;
