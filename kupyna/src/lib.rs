mod sub_units;
#[cfg(test)]
mod tests;

pub struct KupynaH {
    state_size: usize,
    hash_size: usize,
}

impl KupynaH {
    pub fn new(state_size: usize, hash_size: usize) -> Self {
        KupynaH {
            state_size,
            hash_size,
        }
    }

    pub fn default() -> Self {
        KupynaH {
            state_size: 1024,
            hash_size: 512,
        }
    }

    pub fn hash(&self, message: Vec<u8>, length: Option<usize>) -> Result<Vec<u8>, &'static str> {
        let mut message = message;
        let message_length: usize;
        if let Some(len) = length {
            if len > message.len() * 8 {
                return Err("Message length is less than the provided length");
            }

            let mut trimmed_message = message[..(len / 8)].to_vec();

            if len % 8 != 0 {
                let extra_byte = message[len / 8];
                let extra_bits = len % 8;
                let mask = 0xFF << (8 - extra_bits);
                trimmed_message.push(extra_byte & mask);
            }

            message = trimmed_message;
            message_length = len;
        } else {
            message_length = message.len() * 8;
        }

        let padded_message = pad_message(&message, message_length, self.state_size);

        let blocks = divide_into_blocks(&padded_message, self.state_size);

        let mut init_vector: Vec<u8> = vec![0; self.state_size / 8];
        init_vector[0] = 0x80; // set the first bit of this init vector to high

        let fin_vector = sub_units::plant(blocks, &init_vector);

        let hash = truncate(&fin_vector, self.hash_size);

        Ok(hash)
    }
}

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

// Keep the standalone function for backward compatibility
pub fn hash(message: Vec<u8>, length: Option<usize>) -> Result<Vec<u8>, &'static str> {
    KupynaH::default().hash(message, length)
}