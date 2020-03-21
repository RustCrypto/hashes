/***************************************************************************************************
** LIBRARY NAME:   skein
**
** PURPOSE:        this library lets you use the skein algorithm as a hash function
**
** PUBLIC CONSTS:  (none)
**
** PUBLIC TYPES:   BitSequence, DataLength, HashReturn, HashState
**
** PUBLIC FUNCS:   init -> HashReturn, update -> HashReturn, final -> HashReturn,
**                 output -> HashReturn, hash -> HashReturn
**
** NOTES:          (none)
***************************************************************************************************/

extern crate skein;
mod constants;
#[allow(unused_imports)]
mod debug;

//typedefs
pub type BitSequence = u8;
pub type DataLength = u64;

//this is an error code mapping
pub enum HashReturn {
    #[allow(non_camel_case_types)]
    SUCCESS,
    #[allow(non_camel_case_types)]
    FAIL,
    #[allow(non_camel_case_types)]
    BAD_HASHBITLEN
}

pub struct HashState {
    hash_bit_len : usize,
    processed_first_block : bool,
    buffer_index : usize,
    message_buffer : [u8; constants::MAX_BLOCK_SIZE_BYTES],
    skein_block : skein::typedefs::UbiChainBlock,
}

impl HashState {
/***************************************************************************************************
** FUNCTION NAME:  new
**
** PURPOSE:        (constructor)
**
** ARGUMENTS:      hash_bit_size = the size of the hash in bits
**                 block_bit_size = the size of the block in bits
**
** RETURN:         a brand new hash state with the parameters inputed!
**
** NOTES:          (none)
***************************************************************************************************/
    pub fn new(hash_bit_size : usize, block_bit_size : usize)->HashState{
        if hash_bit_size != 256 &&  hash_bit_size != 512 && hash_bit_size != 1024{
             panic!("invalid hash size");
        }
        if block_bit_size != 256 && block_bit_size != 512 && block_bit_size !=1024{
            panic!("invalid block size");
        }
        return HashState {
            hash_bit_len : hash_bit_size,
            processed_first_block : false,
            buffer_index : 0,
            message_buffer : [0 as u8; constants::MAX_BLOCK_SIZE_BYTES],
            skein_block : skein::typedefs::UbiChainBlock::new(block_bit_size)
        }
    }
}

/***************************************************************************************************
** FUNCTION NAME:  init
**
** PURPOSE:        initializes the first block for hashing-
**
** ARGUMENTS:      state = the state that gets operated on
**                 hash_bit_len = the number of bits in the hash
**
** RETURN:         SUCCESS (0)= operation succeeded
**                 FAIL (1)= operation failed
**                 BAD_HASHBITLEN (2) = the length specified for hashing was bad
**
** NOTES:          (none)
***************************************************************************************************/
pub fn init (state : &mut HashState, hash_bit_len : usize) -> HashReturn {
    skein::process_configuration_block(&mut state.skein_block, 0x33414853, 1, hash_bit_len as u64,0,
    0,0);
    return HashReturn::SUCCESS;
}

/***************************************************************************************************
** FUNCTION NAME:  load
**
** PURPOSE:        loads a hash state up to the size of the block
**
** ARGUMENTS:      state = the state that gets operated on
**                 data_stream = the location of the data in memory
**                 data_offset = how much to offset the data_stream by when reading values
**                 data_length_bytes = the size of the data in bytes
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn load (state : &mut HashState, data_stream : &u8, data_offset : u64, data_length_bytes : usize) {
    //debug::zz_print_message("fn load called");
    if state.buffer_index + data_length_bytes > state.skein_block.block_byte_len{
        panic!("data length too big!!!");
    } else {
        //debug::zz_print_message("fn load -> working");
        unsafe {
            let mut ds : u64;
            let mut pointer_index : u64= 0;
            for i in state.buffer_index..(state.buffer_index + data_length_bytes){
                ds = (data_stream as *const u8)as u64 + data_offset + pointer_index;
                state.message_buffer[i] = *(ds as *const u8);
                pointer_index+=1;
            }
        }
        //debug::zz_print_message("fn load -> loaded");
        state.buffer_index+=data_length_bytes;
    }
}

/***************************************************************************************************
** FUNCTION NAME:  update
**
** PURPOSE:        updates the hash by an arbitrary number of bytes of new data.
**
**
** ARGUMENTS:      state = the state that gets operated on
**                 hash_bit_len = the number of bits in the hash
**                 data = the location of raw data
**                 data_bit_len = the amount of data to be processed
**
** RETURN:         SUCCESS (0)= operation succeeded
**                 FAIL (1)= operation failed
**                 BAD_HASHBITLEN (2) = the length specified for hashing was bad
**
** NOTES:          this method is is used when the programmer doesn't know ahead of time how much
**                 data is to be hashed or when all the data that needs to be hashed is not entirely
**                 in memory. this assumes that the config block was already initialized
***************************************************************************************************/
#[allow(unused_variables)]//hash bit len is in the sha3 api we'll just leave it there
pub fn update (state : &mut HashState, hash_bit_len : usize, data : &BitSequence, data_bit_len :
DataLength)-> HashReturn{
    if data_bit_len > 0 && (data_bit_len%8 == 0){

    //calculate how much data is to be processed_first_block
        let mut data_byte_len : usize = data_bit_len as usize/8;
        let block_byte_len : usize = state.skein_block.block_byte_len;

    //calculate if there are blocks to be completed
        let blocks_to_be_completed : bool;
        if state.buffer_index + data_byte_len > block_byte_len {
            blocks_to_be_completed = true;
            data_byte_len = data_byte_len - block_byte_len + state.buffer_index;
        } else {
            blocks_to_be_completed = false;
        }

    //calculate number of regular blocks to process and the final block
        let mut num_regular_blocks : usize = data_byte_len/block_byte_len;
        let mut remainder : usize = data_byte_len%block_byte_len;
        //remember never process the last block... let the final function do that
        if remainder == 0 && num_regular_blocks > 0 {
            remainder = block_byte_len;
            num_regular_blocks = num_regular_blocks -1;
        }

    //complete blocks
        let mut offset : usize = 0;
        if blocks_to_be_completed && (remainder>0){
            offset += state.skein_block.block_byte_len - state.buffer_index;
            load(state,data,0,offset);
            state.buffer_index = 0;
            if !state.processed_first_block {
                state.processed_first_block = true;
                skein::process_first_message_block(&mut (state.skein_block),
                &(state.message_buffer[0]));
            } else {
                skein::process_regular_message_block(&mut state.skein_block,
                &state.message_buffer[0]);
            }
        }

    //regular blocks
        for i in 0..num_regular_blocks {
            load(state,data,(offset+i*block_byte_len)as u64,block_byte_len);
            state.buffer_index = 0;
            skein::process_regular_message_block(&mut state.skein_block,&state.message_buffer[0]);
        }

    //load for next round
        load(state,data,(offset+num_regular_blocks*block_byte_len)as u64,remainder);
        return HashReturn::SUCCESS;
    } else {
        return HashReturn::BAD_HASHBITLEN;
    }
}

/***************************************************************************************************
** FUNCTION NAME:  output
**
** PURPOSE:        this applies the output transform and spits out the final hash value
**
** ARGUMENTS:      state = the state that gets operated on
**                 hashval = the final hash value
**
** RETURN:         SUCCESS (0)= operation succeeded
**                 FAIL (1)= operation failed
**                 BAD_HASHBITLEN (2) = the length specified for hashing was bad
**
** NOTES:          this assumes that the data has already been padded
***************************************************************************************************/
pub fn output (state : &mut HashState, hashval : &mut BitSequence)->HashReturn{
    skein::process_output_block(&mut state.skein_block, hashval, state.hash_bit_len);
    return HashReturn::SUCCESS;
}

/***************************************************************************************************
** FUNCTION NAME:  pad_block_if_necessary
**
** PURPOSE:        pads a block if necessary
**
** ARGUMENTS:      hs = hash state
**                 remainder = the final hash value
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn pad_block_if_necessary(hs : &mut HashState){
    if hs.buffer_index != hs.skein_block.block_byte_len {
        for i in hs.buffer_index..hs.skein_block.block_byte_len {
            hs.message_buffer[i] = 0x00;
        }
    }
    hs.buffer_index = 0;
}

/***************************************************************************************************
** FUNCTION NAME:  last
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      hs = hash state being operated on
**                 data = the data to be loaded
**                 offset = the offset in the data
**                 block_bit_len = the block bit length
**                 remainder = the number of bytes left over
**
** RETURN:         void
**
** NOTES:          the original api listed the function as final, but it is a keyword in rust
***************************************************************************************************/
pub fn last(hs : &mut HashState) {
    let process_len : usize = hs.buffer_index*8;
    pad_block_if_necessary(hs);
    skein::process_final_message_block(&mut hs.skein_block, & hs.message_buffer[0],
    process_len);
}

/***************************************************************************************************
** FUNCTION NAME:  hash
**
** PURPOSE:        gets the hash value specified
**
** ARGUMENTS:      hash_bit_len = the number of bits in the hash
**                 data = the location of data
**                 data_bit_len = the number of bits in the data to be hashed
**                 hashval = the final hash value
**
** RETURN:         SUCCESS (0)= operation succeeded
**                 FAIL (1)= operation failed
**                 BAD_HASHBITLEN (2) = the length specified for hashing was bad
**
** NOTES:          this method is used when all the data needed to be hashed is already in memory.
**                 block_bit_len was added as a parameter so the user can specify it at run time
***************************************************************************************************/
pub fn hash (block_bit_len : usize, hash_bit_len : usize, data : & BitSequence, data_bit_len :
DataLength, hashval : &mut  BitSequence) -> HashReturn {
    let mut hs : HashState = HashState::new(block_bit_len, hash_bit_len);
    init(&mut hs, hash_bit_len);
    update(&mut hs, hash_bit_len, data, data_bit_len);
    last(&mut hs);
    output(&mut hs, hashval);
    return HashReturn::SUCCESS;
}
