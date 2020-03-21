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
extern crate rust_threefish;

pub type Block = rust_threefish::typedefs::Block; //the state that gets operated on
pub type Key = rust_threefish::typedefs::Key; //the key for a block
pub type Tweak = rust_threefish::typedefs::Tweak; //a weird modifier variable thingy
/***************************************************************************************************
** STRUCT NAME:      UbiChainBlock
**
** PURPOSE:          groups together all the data structures used for ubi chaining
**
** PUBLIC VARIABLES: block_bit_len, chain_block, key_instance, tweak, message_operating_copy,
**                   message_final_add_copy, message_buffer, message_buffer_index
**
** PUBLIC FUNCTIONS: new
**
** NOTES:            (none)
***************************************************************************************************/
pub struct UbiChainBlock {
    pub block_bit_len : usize,
    pub block_byte_len : usize,
    pub block_word_len : usize,

    pub chain_block : Key, //the chain block also acts as the key in threefish
    pub tweak : Tweak, //a weird modifier variable thingy

    pub message_operating_copy : Block, //this is the copy of the message that gets operated on
    pub message_final_add_copy : Block //this is the copy of the message that gets added at the end
}

impl UbiChainBlock {
/***************************************************************************************************
** FUNCTION NAME:  new
**
** PURPOSE:        (constructor)
**
** ARGUMENTS:      block_bit_size = the size of the block in bits
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
    pub fn new (block_bit_size : usize) -> UbiChainBlock {
        UbiChainBlock {
            block_word_len : block_bit_size/64,
            block_byte_len : block_bit_size/8,
            block_bit_len : block_bit_size,
            chain_block : [0 as u64;constants::MAX_BLOCK_SIZE_WORDS+1],
            tweak : [0 as u64;constants::TWEAK_WORDS],
            message_operating_copy : [0 as u64;constants::MAX_BLOCK_SIZE_WORDS],
            message_final_add_copy : [0 as u64;constants::MAX_BLOCK_SIZE_WORDS],
        }
    }
}
