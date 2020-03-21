/***************************************************************************************************
** MODULE NAME:    debug
**
** PURPOSE:        useful functions used for debugging in this specific library
**
** PUBLIC CONSTS:  (see all below)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   zz_print_message,  zz_print_ubi_chain
**
** NOTES:          all functions begin with zz to make it easier to comment out
***************************************************************************************************/

use crate::typedefs;

/***************************************************************************************************
** FUNCTION NAME:  zz_print_message
**
** PURPOSE:        prints a debugging message
**
** ARGUMENTS:      message = the message to be printed
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
** FUNCTION NAME:  zz_print_ubi_chain
**
** PURPOSE:        prints a debugging message
**
** ARGUMENTS:      message = the message to be printed
**                 ubi_chain = the UbiChainBlock to print out values for
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)]
pub fn zz_print_ubi_chain(message : &str, ubi_chain: &typedefs::UbiChainBlock){
    println!();
    println!("{} the ubi chain is:", message);
    println!("the tweak is: {:016X} {:016X}", ubi_chain.tweak[0], ubi_chain.tweak[1]);
    println!("the chain block is:");

    let rounds : usize = ubi_chain.block_word_len/4;
    for i in 0..rounds{
        for j in 0..4{
            print!("{:016X} ", ubi_chain.chain_block[i*4+j]);
        }
        println!();
    }
    println!("the operating message is:");
    for i in 0..rounds{
        for j in 0..4{
            print!("{:016X} ", ubi_chain.message_operating_copy[i*4+j]);
        }
        println!();
    }
    println!();
}
