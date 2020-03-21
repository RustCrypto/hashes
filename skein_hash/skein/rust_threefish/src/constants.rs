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

//Key Expansion Definitions
pub const C_240 : u64= 0x1BD11BDAA9FC1A22;
pub const ROUNDS_0256 : usize = 9;
pub const ROUNDS_0512 : usize = 9;
pub const ROUNDS_1024 : usize = 10;

//Round Definitions
pub const KEY_INJECTIONS_PER_ROUND : usize = 2;
pub const MIX_PERMS_PER_KEY_INJECTION : usize = 4;
pub const MAX_SUBROUNDS : usize = 8;

//Tweak Definitions
pub const TWEAK_WORDS : usize = 3;

//Data size definitions
pub const BITS_PER_WORD : usize = 64;
pub const MAX_BLOCK_SIZE_BITS : usize = 1024;
pub const MAX_BLOCK_SIZE_WORDS : usize = MAX_BLOCK_SIZE_BITS/BITS_PER_WORD;

//the values are padded for flexibility in programming
pub const PERMUTE_SCHEDULE_0256:[usize;MAX_BLOCK_SIZE_WORDS]=[0,3,2,1,0,0,0,0,0,0,0,0,0,0,0,0];
pub const PERMUTE_SCHEDULE_0512:[usize;MAX_BLOCK_SIZE_WORDS]=[2,1,4,7,6,5,0,3,0,0,0,0,0,0,0,0];
pub const PERMUTE_SCHEDULE_1024:[usize;MAX_BLOCK_SIZE_WORDS]=
    [0,9,2,13,6,11,4,15,10,7,12,3,14,5,8,1];

//Rotation Constants
pub const ROTATE_CONSTANTS_0256 : [[usize;MAX_BLOCK_SIZE_WORDS/2];MAX_SUBROUNDS] =
    [[14,16,0,0,0,0,0,0],[52,57,0,0,0,0,0,0],[23,40,0,0,0,0,0,0],[5,37,0,0,0,0,0,0],
    [25,33,0,0,0,0,0,0],[46,12,0,0,0,0,0,0],[58,22,0,0,0,0,0,0],[32,32,0,0,0,0,0,0]];
pub const ROTATE_CONSTANTS_0512 : [[usize;MAX_BLOCK_SIZE_WORDS/2];MAX_SUBROUNDS] =
    [[46,36,19,37,0,0,0,0],[33,27,14,42,0,0,0,0],[17,49,36,39,0,0,0,0],[44,9,54,56,0,0,0,0],
    [39,30,34,24,0,0,0,0],[13,50,10,17,0,0,0,0],[25,29,39,43,0,0,0,0],[8,35,56,22,0,0,0,0]];
pub const ROTATE_CONSTANTS_1024 : [[usize;MAX_BLOCK_SIZE_WORDS/2];MAX_SUBROUNDS] =
    [[24,13,8,47,8,17,22,37],[38,19,10,55,49,18,23,52],[33,4,51,13,34,41,59,17],
    [5,20,48,41,47,28,16,25],[41,9,37,31,12,47,44,30],[16,34,56,51,4,53,42,41],
    [31,44,47,46,19,42,44,25],[9,48,35,52,23,31,37,20],];
