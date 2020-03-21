/***************************************************************************************************
** MODULE NAME:    typedefs
**
** PURPOSE:        list of structures used in this library
**
** PUBLIC CONSTS:  (none)
**
** PUBLIC TYPES:   (see below)
**
** PUBLIC FUNCS:   (none)
**
** NOTES:          (none)
***************************************************************************************************/

use crate::constants;

pub type Tweak = [u64;constants::TWEAK_WORDS];

pub type Block = [u64;constants::MAX_BLOCK_SIZE_WORDS];

pub type Key = [u64;constants::MAX_BLOCK_SIZE_WORDS+1];

pub type PermuteSchedule = [usize;constants::MAX_BLOCK_SIZE_WORDS];

pub type RotateConstants = [[usize;constants::MAX_BLOCK_SIZE_WORDS/2];constants::MAX_SUBROUNDS];
