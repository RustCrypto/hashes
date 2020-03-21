/***************************************************************************************************
** MODULE NAME:    constants
**
** PURPOSE:        the variables that should stay the same through the library
**
** PUBLIC CONSTS:  (see all below)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   (none)
**
** NOTES:          (none)
***************************************************************************************************/
extern crate rust_threefish;

//Data constants
pub const MAX_BLOCK_SIZE_WORDS : usize = rust_threefish::constants::MAX_BLOCK_SIZE_WORDS;
pub const BYTES_PER_WORD : usize = rust_threefish::constants::BITS_PER_WORD/8;

//not sure but don't think i need this
pub const MAX_ROUNDS : usize = rust_threefish::constants::ROUNDS_1024;

//tweak constants
pub const TWEAK_WORDS : usize = rust_threefish::constants::TWEAK_WORDS;
pub const TWEAK_TYPE_KEY : u8 = 0;
pub const TWEAK_TYPE_CONFIGURATION : u8  = 4;
pub const TWEAK_TYPE_PERSONALIZATION : u8  = 8;
pub const TWEAK_TYPE_PUBLIC_KEY : u8  = 12;
pub const TWEAK_TYPE_KEY_IDENTIFIER : u8  = 16;
pub const TWEAK_TYPE_NONCE : u8  = 20;
pub const TWEAK_TYPE_MESSAGE : u8  = 48;
pub const TWEAK_TYPE_OUTPUT : u8  = 63;
