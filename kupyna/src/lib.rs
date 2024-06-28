#[cfg(test)]
mod tests;
mod sub_units;

const STATE_SIZE: usize = 1024;
const HASH_SIZE: usize = 512;

const MAX_MESSAGE_LENGTH: usize = 18446744073709551615;

fn pad_message(message: &[u8], msg_len_bits: usize, state_size: usize) -> Vec<u8> {
    let round_msg_len = message.len() * 8;
    let d =
        ((-((round_msg_len + 97) as isize) % (state_size as isize)) + state_size as isize) as usize;

    // Calculate the length of padding to be added
    let pad_len = d / 8;

    // We set the padded message size upfront to reduce allocations
    let padded_len = (msg_len_bits + 7) / 8 + pad_len + 13;
    let mut padded_message = vec![0x00; padded_len];

    // Copy n bits from the input message
    let full_bytes = msg_len_bits / 8;
    let remaining_bits = msg_len_bits % 8;

    padded_message[..full_bytes].copy_from_slice(&message[..full_bytes]);

    if remaining_bits > 0 {
        let last_byte = message[full_bytes];
        padded_message[full_bytes] = last_byte & ((1 << remaining_bits) - 1);
    }

    // Set the n+1'th bit to high
    padded_message[msg_len_bits / 8] |= 1 << (7 - (msg_len_bits % 8));

    // Convert the length to a byte array and copy it into the padded message
    let n_bytes = (msg_len_bits as u128).to_le_bytes(); // message length in little-endian
    padded_message[padded_len - 12..].copy_from_slice(&n_bytes[0..12]);

    padded_message
}

fn divide_into_blocks(padded_message: &[u8], state_size: usize) -> Vec<&[u8]> {
    padded_message.chunks(state_size / 8).collect()
}

fn truncate(block: &[u8], n: usize) -> Vec<u8> {
    let bytes_to_keep = n / 8;
    let start_index = if block.len() > bytes_to_keep {
        block.len() - bytes_to_keep
    } else {
        0
    };
    block[start_index..].to_vec()
}

pub fn hash(message: Vec<u8>, length: Option<usize>) -> Result<Vec<u8>, &'static str> {
    let mut message = message;
    let message_length: usize;
    if let Some(len) = length {
        if len > MAX_MESSAGE_LENGTH {
            return Err("Message is too long");
        }
        if len > message.len() * 8 {
            return Err("Message length is less than the provided length");
        }

        let mut trimmed_message = message[..(len/8)].to_vec();

        if len % 8 != 0 {
            let extra_byte = message[len/8];
            let extra_bits = len % 8;
            let mask = 0xFF << (8 - extra_bits);
            trimmed_message.push(extra_byte & mask);
        }

        message = trimmed_message;
        message_length = len;

    } else {
        if message.len() * 8 > MAX_MESSAGE_LENGTH {
            return Err("Message is too long");
        }
        message_length = message.len() * 8;
    }

    let padded_message = pad_message(&message, message_length, STATE_SIZE);

    let blocks = divide_into_blocks(&padded_message, STATE_SIZE);

    let mut init_vector: Vec<u8> = vec![0; STATE_SIZE/8];
    init_vector[0] = 0x80; // set the first bit of this init vector to high


    let fin_vector = sub_units::plant(blocks, &init_vector);

    let hash = truncate(&fin_vector, HASH_SIZE);

    Ok(hash)
}

