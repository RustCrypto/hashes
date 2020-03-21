/***************************************************************************************************
** LIBRARY NAME:   rust_threefish
**
** PURPOSE:        this is the module that encrypts and decrypts blocks using the threefish algo
**
** PUBLIC CONSTS:  (see module constants)
**
** PUBLIC TYPES:   (see module typedefs)
**
** PUBLIC FUNCS:   encrypt_block -> void, decrypt_block -> void
**
** NOTES:          (none)
***************************************************************************************************/

pub mod typedefs;
pub mod constants;
mod block_operations;
mod modulo_2_64;
mod debug;

/***************************************************************************************************
** FUNCTION NAME:  encrypt_block
**
** PURPOSE:        encrypts a block
**
** ARGUMENTS:      block = the block to be encrypted
**                 key  = the key used for encryption
**                 tweak = a modifier structure used specifically in threefish
**                 key_bit_len = the length of the key in bits
**                 block_bit_len = the length of the block in bits
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn encrypt_block(block : &mut typedefs::Block, key : &mut typedefs::Key, tweak : &
typedefs::Tweak, key_bit_len : usize, block_bit_len : usize){

    if block_bit_len != 256 && block_bit_len !=512 && block_bit_len !=1024{
        panic!("invalid block len");
    } else if key_bit_len != block_bit_len {
        panic!("key sizes do not match block sizes");
    } else {
        let permute_schedule : & typedefs::PermuteSchedule;
        let rotate_constants : & typedefs::RotateConstants;
        let rounds : usize;
        if block_bit_len == 256 {
            rounds = constants::ROUNDS_0256;
            permute_schedule = & constants::PERMUTE_SCHEDULE_0256;
            rotate_constants = & constants::ROTATE_CONSTANTS_0256;
        } else if block_bit_len == 512 {
            rounds = constants::ROUNDS_0512;
            permute_schedule = & constants::PERMUTE_SCHEDULE_0512;
            rotate_constants = & constants::ROTATE_CONSTANTS_0512;
        } else if block_bit_len == 1024 {
            rounds = constants::ROUNDS_1024;
            permute_schedule = & constants::PERMUTE_SCHEDULE_1024;
            rotate_constants = & constants::ROTATE_CONSTANTS_1024;
        } else {
            panic!("non standard block size");
        }

        block_operations::encrypt_block(block, key, tweak, block_bit_len/constants::BITS_PER_WORD,
        permute_schedule, rotate_constants, rounds);
    }
}

/***************************************************************************************************
** FUNCTION NAME:  decrypt_block
**
** PURPOSE:        decrypts a block
**
** ARGUMENTS:      block = the block to be encrypted
**                 key  = the key used for encryption
**                 tweak = a modifier structure used specifically in threefish
**                 key_bit_len = the length of the key in bits
**                 block_bit_len = the length of the block in bits
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn decrypt_block(block : &mut typedefs::Block, key : &mut typedefs::Key, tweak : &
typedefs::Tweak, key_bit_len : usize, block_bit_len : usize){
    if block_bit_len != 256 && block_bit_len !=512 && block_bit_len !=1024{
        panic!("invalid block len");
    }else if key_bit_len != block_bit_len {
        panic!("key sizes do not match block sizes");
    } else {

        let permute_schedule : & typedefs::PermuteSchedule;
        let rotate_constants : & typedefs::RotateConstants;
        let rounds : usize;
        if block_bit_len == 256 {
            rounds = constants::ROUNDS_0256;
            permute_schedule = & constants::PERMUTE_SCHEDULE_0256;
            rotate_constants = & constants::ROTATE_CONSTANTS_0256;
        } else if block_bit_len == 512 {
            rounds = constants::ROUNDS_0512;
            permute_schedule = & constants::PERMUTE_SCHEDULE_0512;
            rotate_constants = & constants::ROTATE_CONSTANTS_0512;
        } else if block_bit_len == 1024 {
            rounds = constants::ROUNDS_1024;
            permute_schedule = & constants::PERMUTE_SCHEDULE_1024;
            rotate_constants = & constants::ROTATE_CONSTANTS_1024;
        } else {
            panic!("non standard block size");
        }

        block_operations::decrypt_block(block, key, tweak, block_bit_len/constants::BITS_PER_WORD,
        permute_schedule, rotate_constants, rounds);
    }
}
