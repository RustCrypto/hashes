/***************************************************************************************************
** MODULE NAME:    block_operations
**
** PURPOSE:        handles block operations for threefish
**
** PUBLIC CONSTS:  (none)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   encrypt_block -> void, decrypt block -> void
**
** NOTES:          (none)
***************************************************************************************************/

use crate::constants;
use crate::typedefs;
use crate::modulo_2_64;

#[allow(unused_imports)]
use crate::debug;

/***************************************************************************************************
** FUNCTION NAME:  add_subkey
**
** PURPOSE:        injects the designated subkey into the state
**
** ARGUMENTS:      state = the block that is being operated on
**                 key = the key
**                 tweak = a modifier structure used specifically in threefish
**                 round = the round
**                 key_round = the key round
**                 word_count = the number of words
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn add_subkey(state : &mut typedefs::Block, key : &mut typedefs::Key, tweak : & typedefs::Tweak,
round : usize, key_round : usize, word_count : usize){
//get parity
    key[word_count] = constants::C_240;
    for i in 0..word_count{
        key[word_count] ^= key[i];
    }

//define r
    let r : usize = constants::KEY_INJECTIONS_PER_ROUND*round + key_round +1;

//add key
    for i in 0..word_count {
        state[i] = modulo_2_64::add(state[i],key[(r+i)%(word_count+1)]);
    }
    state[word_count-3] = modulo_2_64::add(state[word_count-3],tweak[r%3]);
    state[word_count-2] = modulo_2_64::add(state[word_count-2],tweak[(r+1)%3]);
    state[word_count-1] = modulo_2_64::add(state[word_count-1],r as u64);
}

/***************************************************************************************************
** FUNCTION NAME:  minus_subkey
**
** PURPOSE:        takes the designated subkey out of the state
**
** ARGUMENTS:      state = the block that is being operated on
**                 key = the key
**                 tweak = a modifier structure used specifically in threefish
**                 round = the round
**                 key_round = the key round
**                 word_count = the number of words
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn minus_subkey(state : &mut typedefs::Block, key : &mut typedefs::Key, tweak : & typedefs::Tweak,
round : usize, key_round : usize, word_count : usize){
//get parity
    key[word_count] = constants::C_240;
    for i in 0..word_count{
        key[word_count] ^= key[i];
    }

//define r
    let r : usize = constants::KEY_INJECTIONS_PER_ROUND*round + key_round +1;

//minus key
    state[word_count-3] = modulo_2_64::minus(state[word_count-3],tweak[r%3]);
    state[word_count-2] = modulo_2_64::minus(state[word_count-2],tweak[(r+1)%3]);
    state[word_count-1] = modulo_2_64::minus(state[word_count-1],r as u64);
    for i in 0..word_count {
        state[i] = modulo_2_64::minus(state[i],key[(r+i)%(word_count+1)]);
    }

}

/***************************************************************************************************
** FUNCTION NAME:  rotate_64_left
**
** PURPOSE:        rotates a 64 bit entity to the left by a specified number
**
** ARGUMENTS:      word = the 64 bit entity to rotate
**                 N = the number of bits to shift by
**
** RETURN:         a 64 bit entity that has been rotated
**
** NOTES:          (none)
***************************************************************************************************/
fn rotate_64_left(word : u64, n : usize) -> u64{
    return (word << n) | (word >> (64-n));
}

/***************************************************************************************************
** FUNCTION NAME:  rotate_64_right
**
** PURPOSE:        rotates a 64 bit entity to the right by a specified number
**
** ARGUMENTS:      word = the 64 bit entity to rotate
**                 N = the number of bits to shift by
**
** RETURN:         a 64 bit entity that has been rotated
**
** NOTES:          (none)
***************************************************************************************************/
fn rotate_64_right(word : u64, n : usize) -> u64{
    return (word >> n) | (word << (64-n));
}

/***************************************************************************************************
** FUNCTION NAME:  mix
**
** PURPOSE:        mixes 2 64bit words
**
** ARGUMENTS:      left_word = the first word
**                 right_word = the second word
**                 rotate_constant = the amount to rotate by
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn mix(state : &mut typedefs::Block, l : usize, rotate_constant : usize){
    state[2*l] =  modulo_2_64::add(state[2*l+1],state[2*l]);
    state[2*l+1] = rotate_64_left(state[2*l+1], rotate_constant);
    state[2*l+1] ^= state[2*l];
}

/***************************************************************************************************
** FUNCTION NAME:  unmix
**
** PURPOSE:        unmixes 2 64bit words
**
** ARGUMENTS:      left_word = the first word
**                 right_word = the second word
**                 rotate_constant = the amount to rotate by
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn unmix(state : &mut typedefs::Block, l : usize, rotate_constant : usize){
    state[2*l+1] ^= state[2*l];
    state[2*l+1] = rotate_64_right(state[2*l+1], rotate_constant);
    state[2*l] = modulo_2_64::minus(state[2*l],state[2*l+1]);
}

/***************************************************************************************************
** FUNCTION NAME:  permute
**
** PURPOSE:        permutes the state
**
** ARGUMENTS:      state = the block being operated on
**                 permute_schedule = the permute_schedule to be used
**                 word_count = the number of words in the state
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn permute(state : &mut typedefs::Block, permute_schedule : &typedefs::PermuteSchedule, word_count :
usize){
    let mut temp : typedefs::Block = [0;16];
    for i in 0..word_count{
        temp[i] = state[permute_schedule[i]];
    }
    for i in 0..word_count {
        state[i] = temp[i];
    }
}



/***************************************************************************************************
** FUNCTION NAME:  unpermute
**
** PURPOSE:        unpermutes the state
**
** ARGUMENTS:      state = the block being operated on
**                 permute_schedule = the permute_schedule to be used
**                 word_count = the number of words in the state
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn unpermute(state : &mut typedefs::Block, permute_schedule : &typedefs::PermuteSchedule, word_count
: usize){
    let mut temp : [u64;16] =  [0;16];
    for i in 0..word_count{
        temp[permute_schedule[i]] = state[i];
    }
    for i in 0..word_count {
        state[i] = temp[i];
    }
}

/***************************************************************************************************
** FUNCTION NAME:  mix_peremute
**
** PURPOSE:        mixes and permutes the state
**
** ARGUMENTS:      state = the block being operated on
**                 subround = the subround that the encryption algorithm is on
**                 permute_schedule = (self explanatory)
**                 rotate_constants = (self explanatory)
**                 word_count = the number of words in the state
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn mix_permute(state : &mut typedefs::Block, subround : usize, rotate_constants : &
typedefs::RotateConstants, permute_schedule :& typedefs::PermuteSchedule, word_count : usize){
    for i in 0..word_count/2{
        mix(state, i, rotate_constants[subround][i]);
    }
    permute(state, permute_schedule, word_count);
}


/***************************************************************************************************
** FUNCTION NAME:  unmix_unperemute
**
** PURPOSE:        unmixes and unpermutes the state
**
** ARGUMENTS:      state = the block being operated on
**                 subround = the subround that the encryption algorithm is on
**                 permute_schedule = (self explanatory)
**                 rotate_constants = (self explanatory)
**                 word_count = the number of words in the state
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn unmix_unpermute(state : &mut typedefs::Block, subround : usize, rotate_constants : &
typedefs::RotateConstants, permute_schedule :& typedefs::PermuteSchedule, word_count : usize){
    unpermute(state, permute_schedule, word_count);
    for i in (0..word_count/2).rev(){
        unmix(state, i, rotate_constants[subround][i]);
    }
}

/***************************************************************************************************
** FUNCTION NAME:  encrypt
**
** PURPOSE:        scrambles the state
**
** ARGUMENTS:      state = the block being operated on
**                 key = the key used to scramble the state
**                 tweak = a modifier structure used specifically in threefish
**                 word_count = the number of words in the state
**                 permute_schedule = (self explanatory)
**                 rotate_constants = (self explanatory)
**                 rounds = the number of rounds in the cipher to go through
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn encrypt_block(state : &mut typedefs::Block, key : &mut typedefs::Key, tweak : &
typedefs::Tweak, word_count : usize, permute_schedule: &typedefs::PermuteSchedule, rotate_constants
: &typedefs::RotateConstants, rounds : usize){
//first key injection
    for i in 0..word_count {
        state[i] = modulo_2_64::add(state[i],key[(i)%(word_count+1)]);
    }
    state[word_count-3] = modulo_2_64::add(state[word_count-3],tweak[0]);
    state[word_count-2] = modulo_2_64::add(state[word_count-2],tweak[1]);

//process rounds
    for i in 0..rounds{
        for j in 0..constants::KEY_INJECTIONS_PER_ROUND {
            for k in 0..constants::MIX_PERMS_PER_KEY_INJECTION {
                mix_permute(state, constants::MIX_PERMS_PER_KEY_INJECTION*j+k, rotate_constants,
                    permute_schedule, word_count);
            }
            add_subkey(state, key, tweak, i, j, word_count);
        }
    }
}

/***************************************************************************************************
** FUNCTION NAME:  decrypt
**
** PURPOSE:        unscrambles the state
**
** ARGUMENTS:      state = the block being operated on
**                 key = the key used to scramble the state
**                 tweak = a modifier structure used specifically in threefish
**                 word_count = the number of words in the state
**                 permute_schedule = (self explanatory)
**                 rotate_constants = (self explanatory)
**                 rounds = the number of rounds in the cipher to go through
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
pub fn decrypt_block(state : &mut typedefs::Block, key : &mut typedefs::Key, tweak : &
typedefs::Tweak, word_count : usize, permute_schedule: &typedefs::PermuteSchedule, rotate_constants
: &typedefs::RotateConstants, rounds : usize){
//unprocess rounds
    for i in (0..rounds).rev(){
        for j in (0..constants::KEY_INJECTIONS_PER_ROUND).rev() {
            minus_subkey(state, key, tweak, i, j, word_count);
            for k in (0..constants::MIX_PERMS_PER_KEY_INJECTION).rev(){
                unmix_unpermute(state,constants::MIX_PERMS_PER_KEY_INJECTION*j+k, rotate_constants,
                    permute_schedule, word_count);
            }
        }
    }
//undo first key injection
    state[word_count-3] = modulo_2_64::minus(state[word_count-3],tweak[0]);
    state[word_count-2] = modulo_2_64::minus(state[word_count-2],tweak[1]);
    for i in 0..word_count {
        state[i] = modulo_2_64::minus(state[i],key[(i)%(word_count+1)]);
    }
}
