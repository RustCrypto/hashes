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
extern crate skein;
pub const MAX_BLOCK_SIZE_BYTES : usize  = skein::constants::MAX_BLOCK_SIZE_WORDS*
    skein::constants::BYTES_PER_WORD;
