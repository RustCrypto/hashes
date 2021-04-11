use rand::Rng;

const S: usize = 1_120; // s = w * log_2(n/w)
const R: usize = 640;
const SIZE: usize = (S - R) / 8;

// The following seems pretty complex for a padding. Sure there are better ways to do this.
pub fn padding(input_message: &[u8]) -> Vec<[u8; SIZE]> {
    let mut padded_message: Vec<[u8; SIZE]> = Vec::new();
    let length = input_message.len();
    let nmbr_blocks = length / (SIZE);
    // we simply copy the first values of the input_message to the padded_message
    for index in 0..nmbr_blocks {
        let mut block = [0u8; SIZE];
        block.copy_from_slice(&input_message[(index * SIZE)..((index + 1) * SIZE)]);
        padded_message.push(block);
    }

    // Now we handle the last block(s)
    let mut last_block = [0u8; SIZE];
    let mut temp_block = input_message[(nmbr_blocks * SIZE)..].to_vec();

    let last_block_init_size = length % SIZE;

    if last_block_init_size <= SIZE - 8 - 1 {
        let padding_size = SIZE - last_block_init_size - 8;
        let mut padding = vec![0u8; padding_size];
        padding[0] = 0b1000000;

        temp_block.extend_from_slice(&padding);

        temp_block.extend_from_slice(&length.to_be_bytes());

        last_block.copy_from_slice(&temp_block);
        padded_message.push(last_block);
    } else {
        let padding_size = SIZE - last_block_init_size;
        let mut padding = vec![0u8; padding_size];
        padding[0] = 0b1000000;

        temp_block.extend_from_slice(&padding);
        padded_message.push(last_block);

        let mut additional_block = [0u8; SIZE];
        additional_block[SIZE - 8..].clone_from_slice(&length.to_be_bytes());
        padded_message.push(additional_block);
    }

    padded_message
}

fn main() {
    let random_bytes: Vec<u8> = (0..117).map(|_| rand::random::<u8>()).collect();

    let padded = padding(&random_bytes);
    let size = &padded.last().unwrap()[(SIZE - 8)..];
    let expected_size = random_bytes.len().to_be_bytes();
    assert_eq!(size, &expected_size)
}
