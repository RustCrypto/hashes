/***************************************************************************************************
** LIBRARY NAME:   skein
**
** PURPOSE:        this library lets you use the skein algorithm
**
** PUBLIC CONSTS:  (see module constants)
**
** PUBLIC TYPES:   (see module typedefs)
**
** PUBLIC FUNCS:   process_private_key_block, process_configuration_block,
**                 process_personalization_block, process_public_key_block,
**                 process_key_identifier_block, process_nonce_block,
**                 process_first_message_block, process_first_and_last_message_block,
**                 process_regular_message_block, process_final_message_block,
**                 process_output_block
**
** NOTES:          (none)
***************************************************************************************************/

extern crate rust_threefish;
pub mod constants;
pub mod typedefs;
mod debug;
mod tweak;

/***************************************************************************************************
** FUNCTION NAME:  process_block
**
** PURPOSE:        runs data through a full round of ubi chaining with the threefish algorithm
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn process_block(ubi_chain: &mut typedefs::UbiChainBlock){
    //debug::zz_print_ubi_chain("right before processing the block", ubi_chain);
//final update of tweak
    ubi_chain.tweak[2] = ubi_chain.tweak[0] ^ ubi_chain.tweak[1];
//threefish
    rust_threefish::encrypt_block(&mut ubi_chain.message_operating_copy, &mut
    ubi_chain.chain_block, &ubi_chain.tweak, ubi_chain.block_bit_len, ubi_chain.block_bit_len );
//ubi chain
    for i in 0..ubi_chain.block_word_len{
        ubi_chain.chain_block[i] = ubi_chain.message_operating_copy[i] ^
        ubi_chain.message_final_add_copy[i];
    }
    //debug::zz_print_ubi_chain("right after processing the block", ubi_chain);
}

/***************************************************************************************************
** FUNCTION NAME:  load_and_process_block
**
** PURPOSE:        this loads data into the memory and runs data through a full round of ubi
**                 chaining with the threefish algorithm
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn load_and_process_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8){
    let data_pointer : u64 = data as u64;
    unsafe {
        for i in 0..ubi_chain.block_word_len{
            ubi_chain.message_final_add_copy[i] = (*((data_pointer + ((i+1) *
            constants::BYTES_PER_WORD-1) as u64) as *const u8))as u64;
            for j in (0..(constants::BYTES_PER_WORD-1)).rev(){
                ubi_chain.message_final_add_copy[i] = ubi_chain.message_final_add_copy[i] << 8;
                ubi_chain.message_final_add_copy[i] |= (*((data_pointer + (i *
                constants::BYTES_PER_WORD + j) as u64) as *const u8))as u64;
            }
            /*
            ubi_chain.message_final_add_copy[i] = (*((data_pointer + (constants::BYTES_PER_WORD *
             i)as u64) as *const u8))as u64;
            for j in 1..constants::BYTES_PER_WORD{
                ubi_chain.message_final_add_copy[i] = (ubi_chain.message_final_add_copy[i] << 8) |
                (*((data_pointer + (constants::BYTES_PER_WORD*i+j)as u64) as *const u8))as u64;
            }
            */
            ubi_chain.message_operating_copy[i] = ubi_chain.message_final_add_copy[i];
        }
    }

    process_block(ubi_chain);
}

/***************************************************************************************************
** FUNCTION NAME:  process_private_key_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_private_key_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
//configure tweaks
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_KEY);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    load_and_process_block(ubi_chain, data);
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_configuration_block
**
** PURPOSE:        processes the configuration block
**
** ARGUMENTS:      ubi_chain = the chain
**                 schema_identifier = a 4byte value identifying the schema
**                 version = specifies the version
**                 hash_bit_len = the length of the hash in bits
**                 tree_leaf = the number of leaves in the tree 0 if tree hashing is not used
**                 tree_fan = LOOK THIS UP 0 if tree hashing is not used
**                 tree_height = the max height of the tree, 0 if tree hashing is not used
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_configuration_block(ubi_chain: &mut typedefs::UbiChainBlock, schema_identifier :
u32, version : u16, hash_bit_len :u64, tree_leaf : u8, tree_fan : u8, tree_height : u8){
//configure type tweak
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_CONFIGURATION);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[0] = 32;

//load data
    ubi_chain.message_operating_copy[0] = version as u64;
    ubi_chain.message_operating_copy[0] = ubi_chain.message_operating_copy[0]<< 32;
    ubi_chain.message_operating_copy[0] |= schema_identifier as u64;

    ubi_chain.message_operating_copy[1] = (hash_bit_len) as u64;

    ubi_chain.message_operating_copy[2] = tree_height as u64;
    ubi_chain.message_operating_copy[2] = ubi_chain.message_operating_copy[2] << 8;
    ubi_chain.message_operating_copy[2] |= tree_fan as u64;
    ubi_chain.message_operating_copy[2] =  ubi_chain.message_operating_copy[2] << 8;
    ubi_chain.message_operating_copy[2] |= tree_leaf as u64;

    //the other blocks should be zero if the configuration block is always the first block to be
    //processed

    for i in 0..4{
        ubi_chain.message_final_add_copy[i] = ubi_chain.message_operating_copy[i];
    }

    process_block(ubi_chain);

    //reset the tweaks for the next block
    ubi_chain.tweak[0] = 0;
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_personalization_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_personalization_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
//configure tweaks
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_PERSONALIZATION);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    load_and_process_block(ubi_chain, data);
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_public_key_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_public_key_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
//configure tweaks
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_PUBLIC_KEY);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    load_and_process_block(ubi_chain, data);
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}


/***************************************************************************************************
** FUNCTION NAME:  process_key_identifier_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_key_identifier_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
//configure tweaks
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_KEY_IDENTIFIER);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    load_and_process_block(ubi_chain, data);
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_key_nonce_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_nonce_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
//configure tweaks
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_NONCE);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    load_and_process_block(ubi_chain, data);
    ubi_chain.tweak[1] = tweak::set_last_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_first_message_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_first_message_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8){
//configure tweaks -  this is the most common type of block no need to slow the algorithm down
//by constantly unnecessarily modifying the tweak type. but do modify the tweak counter
    println!("process_first_message_block called!");
    ubi_chain.tweak[0] += ubi_chain.block_byte_len as u64;
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_MESSAGE);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    //debug::zz_print_message("=============================================================");
    //debug::zz_print_message("At process_first_message_block");
    load_and_process_block(ubi_chain, data);
    //debug::zz_print_message("=============================================================\n\n\n");
    ubi_chain.tweak[1] = tweak::set_first_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  process_regular_message_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn process_regular_message_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8){
    ubi_chain.tweak[0] += ubi_chain.block_byte_len as u64;
    load_and_process_block(ubi_chain, data);
}

/***************************************************************************************************
** FUNCTION NAME:  process_final_message_block
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 data = memory location of data
**                 unpadded_bit_len = the unpadded length of the message
**
** RETURN:         void
**
** NOTES:          pad the message before running this function
***************************************************************************************************/
pub fn process_final_message_block(ubi_chain: &mut typedefs::UbiChainBlock, data : *const u8,
unpadded_bit_len : usize){
    ubi_chain.tweak[0] += (unpadded_bit_len/8) as u64;
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1],constants::TWEAK_TYPE_MESSAGE);
    //debug::zz_print_message("=============================================================");
    //debug::zz_print_message("At process_final_message_block");
    load_and_process_block(ubi_chain, data);
    //debug::zz_print_message("=============================================================");
    ubi_chain.tweak[1] = tweak::set_pad_off(ubi_chain.tweak[1]);
}

/***************************************************************************************************
** FUNCTION NAME:  convert_to_bytes
**
** PURPOSE:        converts an array of u64s into an array of u8s
**
** ARGUMENTS:      block = the block to convert
**                 destination = where to put the values
**                 word_len = how many 64bit words are being converted
**
** RETURN:         void
**
** NOTES:          was written for little endian machines in least significant bit first mode
***************************************************************************************************/
fn convert_to_bytes(block : &typedefs::Key, destination : *mut u8, word_len : usize){
    let destination_pointer : u64 = destination as u64;
    unsafe { //wooooooo no safety!!!
        for i in 0..word_len{
            for j in 0..constants::BYTES_PER_WORD{
                *((destination_pointer + (constants::BYTES_PER_WORD*i+j)as u64) as *mut u8) =
                (block[i] >> j*8) as u8;
            }
        }
    }
}

/***************************************************************************************************
** FUNCTION NAME:  process_output_block
**
** PURPOSE:        this is the output transform
**
** ARGUMENTS:      ubi_chain = the ubi_chain to operate on
**                 hash_val = where to put the hash value
**                 hash_bit_len = the bit length of the hash
**
** RETURN:         void
**
** NOTES:          make sure there is enough space at hash_val to cover not only the the necessary
**                 bytes but also the overflow which may occur
***************************************************************************************************/
pub fn process_output_block(ubi_chain: &mut typedefs::UbiChainBlock, hash_val : *mut u8,
hash_bit_len: usize){

//configure tweaks
    ubi_chain.tweak[0] = 8; // not sure why this is arbitrarily set to 8. it just is.
    ubi_chain.tweak[1] = tweak::set_type(ubi_chain.tweak[1], constants::TWEAK_TYPE_OUTPUT);
    ubi_chain.tweak[1] = tweak::set_first_on(ubi_chain.tweak[1]);
    ubi_chain.tweak[1] = tweak::set_last_on(ubi_chain.tweak[1]);

//calculate how many iterations are needed
    let mut final_iter : usize = hash_bit_len/ubi_chain.block_bit_len;
    let remainder :usize = hash_bit_len % ubi_chain.block_bit_len;
    if remainder > 0 { final_iter += 1;}


//create a copy of the last chain
    let mut chain_copy : typedefs::Key = [0;constants::MAX_BLOCK_SIZE_WORDS+1];
    for i in 0..ubi_chain.block_word_len{
        chain_copy[i] = ubi_chain.chain_block[i];
    }
//create the output
    for i in 0..final_iter{
    //setup counter block
        for j in 0..ubi_chain.block_word_len - 1{
            ubi_chain.message_final_add_copy[j] = 0;
            ubi_chain.message_operating_copy[j] = 0;
        }
        ubi_chain.message_final_add_copy[ubi_chain.block_word_len - 1] = i as u64;
        ubi_chain.message_operating_copy[ubi_chain.block_word_len - 1] = i as u64;

    //process_block
        //debug::zz_print_message("=============================================================");
        //debug::zz_print_message("at output transform:");
        process_block(ubi_chain);
        //debug::zz_print_message("=============================================================");

    //put bytes into the hash value
        convert_to_bytes(& ubi_chain.chain_block, ((hash_val as u64) +
        (i*ubi_chain.block_byte_len)as u64) as *mut u8, ubi_chain.block_word_len);

    //copy the last chain back in
        for j in 0..ubi_chain.block_word_len{
            ubi_chain.chain_block[j] = chain_copy[j];
        }
    }
}
