/// MD6 constants related to standard mode of operation

pub type Md6Word = u64;
pub type Md6ControlWord = u64;
pub type Md6NodeID = u64;

/// Maximum stack height
pub const MD6_MAX_STACK_HEIGHT: usize = 29;
/// Maximum number of rounds
pub const MD6_MAX_R: usize = 255;
/// Large so that MD6 is fully hierarchical
pub const MD6_DEFAULT_L: usize = 64;

/// Number of bits in a word
pub const MD6_W: usize = 64;
/// Size of compression output in words
pub const MD6_C: usize = 16;
/// Size of compression input block in words
pub const MD6_N: usize = 89;

// These five values give lengths of the components of compression
// input block; they should sum to MD6_N.

// Q words in a compression block (>= 0)
pub const MD6_Q: usize = 15;
/// Key words per compression block (>= 0)
pub const MD6_K: usize = 8;
/// Words for unique node ID (0 or 64/w)
pub const MD6_U: usize = 64 / MD6_W;
/// Words for control word (0 or 64/w)
pub const MD6_V: usize = 64 / MD6_W;
/// Data words per compression block (> 0)
pub const MD6_B: usize = 64;

/// Number of bits in a word (64)
pub const W: usize = MD6_W;
/// Size of compression output in words (16)
pub const C: usize = MD6_C;
/// Size of compression input block in words (89)
pub const N: usize = MD6_N;
/// Q words in a compression block (>= 0) (15)
pub const Q: usize = MD6_Q;
/// Key words per compression block (>= 0) (8)
pub const K: usize = MD6_K;
/// Words for unique node ID (0 or 64/w)
pub const U: usize = MD6_U;
/// Words for control word (0 or 64/w)
pub const V: usize = MD6_V;
/// Data words per compression block (> 0) (64)
pub const B: usize = MD6_B;

/// Index for linear feedback
pub const T0: usize = 17;
/// Index for first input to first and
pub const T1: usize = 18;
/// Index for second input to first and
pub const T2: usize = 21;
/// Index for first input to second and
pub const T3: usize = 31;
/// Index for second input to second and
pub const T4: usize = 67;
/// Last tap
pub const T5: usize = 89;
