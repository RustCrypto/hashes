
/// MD6 constants related to standard mode of operation 

pub type md6_word = u64;
pub type md6_control_word = u64;
pub type md6_nodeID = u64;

pub const md6_max_stack_height: usize = 29; // maximum stack height
pub const md6_max_r: usize = 255; // maximum number of rounds
pub const md6_default_L: usize = 64; // large so that MD6 is fully hierarchical

pub const md6_w: usize = 64; // number of bits in a word
pub const md6_c: usize = 16; // size of compression output in words
pub const md6_n: usize = 89; // size of compression input block in words

/// These five values give lengths of the components of compression
/// input block; they should sum to md6_n. 
pub const md6_q: usize = 15; // Q words in a compression block (>= 0)
pub const md6_k: usize = 8; // key words per compression block (>= 0)
pub const md6_u: usize = 64 / md6_w; // words for unique node ID (0 or 64/w)
pub const md6_v: usize = 64 / md6_w; // words for control word (0 or 64/w)
pub const md6_b: usize = 64; // data words per compression block (> 0)
