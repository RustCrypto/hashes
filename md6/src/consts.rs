/// MD6 constants related to standard mode of operation

pub(crate) type Md6Word = u64;
pub(crate) type Md6ControlWord = u64;
pub(crate) type Md6NodeID = u64;

pub(crate) const MD6_MAX_STACK_HEIGHT: usize = 29; // maximum stack height
pub(crate) const MD6_MAX_R: usize = 255; // maximum number of rounds
pub(crate) const MD6_DEFAULT_L: usize = 64; // large so that MD6 is fully hierarchical

pub(crate) const MD6_W: usize = 64; // number of bits in a word
pub(crate) const MD6_C: usize = 16; // size of compression output in words
pub(crate) const MD6_N: usize = 89; // size of compression input block in words

/// These five values give lengths of the components of compression
/// input block; they should sum to MD6_N.
pub(crate) const MD6_Q: usize = 15; // Q words in a compression block (>= 0)
pub(crate) const MD6_K: usize = 8; // key words per compression block (>= 0)
pub(crate) const MD6_U: usize = 64 / MD6_W; // words for unique node ID (0 or 64/w)
pub(crate) const MD6_V: usize = 64 / MD6_W; // words for control word (0 or 64/w)
pub(crate) const MD6_B: usize = 64; // data words per compression block (> 0)
