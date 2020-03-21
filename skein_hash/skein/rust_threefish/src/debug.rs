/***************************************************************************************************
** MODULE NAME:    debug
**
** PURPOSE:        useful functions used for debugging in this specific library
**
** PUBLIC CONSTS:  (see all below)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   zz_print_message,  zz_print_block
**
** NOTES:          all functions begin with zz to make it easier to comment out
***************************************************************************************************/

use crate::typedefs;

/***************************************************************************************************
** FUNCTION NAME:  zz_print_message
**
** PURPOSE:        prints a simple message
**
** ARGUMENTS:      message = the message to print
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)] // this just turns off the annoying compiler warnings
pub fn zz_print_message(message : &str){
    println!("{}", message);
}

/***************************************************************************************************
** FUNCTION NAME:  zz_print_block
**
** PURPOSE:        prints a block into standard output
**
** ARGUMENTS:      block = the block to print
**                 word_count = the number of words in the block
**                 mode = should be "encrypting" or "decrypting"
**                 round = the round of encryption
**                 key_round = the round of key injection
**                 subround = the subround
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)]
pub fn zz_print_block(block : &typedefs::Block, word_count : usize, mode : &str , round : usize,
key_round : usize, sub_round : usize){
    println!("\n================PRINTING A BLOCK ==================");
    println!("Block Size in Bits: {}", word_count*64);
    println!("mode: {}",mode);
    println!("round: {}   key round: {}  sub_round: {}", round, key_round, sub_round);
    for i in 0..word_count{
        print!("{:016X} ", block[i]);
    }
    println!();
}
