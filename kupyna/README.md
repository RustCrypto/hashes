# Kupyna Hash Function Implementation in Rust

## Overview

The Kupyna hash function is a cryptographic hash developed in Ukraine, designed for high security and efficiency. This implementation supports generating hash codes of various lengths.

## Author

Joshua Koudys  
Email: [josh@qaribou.com](mailto:josh@qaribou.com)

## Summary

Kupyna is a hash function standardized in Ukraine as DSTU 7564:2014. It is designed to provide a high level of security with a focus on robustness against various cryptographic attacks. The function supports different hash lengths, providing flexibility in usage depending on security requirements.

### Key Features of Kupyna:
- **High Security:** Resistant to known cryptographic attacks.
- **Efficiency:** Optimized for performance.
- **Flexibility:** Supports variable hash output lengths.

## Implementation Details

### Functions

- **`pad_message`**: Pads the input message according to the Kupyna padding scheme.
- **`divide_into_blocks`**: Divides the padded message into fixed-size blocks.
- **`t_xor_l`**: Placeholder for the T⊕l transformation (to be implemented).
- **`t_plus_l`**: Placeholder for the T+l transformation (to be implemented).
- **`r_l_n`**: Truncates the block to the desired number of bits.
- **`kupyna_hash`**: Main function to compute the Kupyna hash of a given message.
- **`xor_bytes`**: Utility function to perform bitwise XOR on two byte slices.

### Usage

To compute the hash of a message using this implementation, you can call the `kupyna_hash` function with your message and desired hash length. Below is a basic usage example:

```rust
fn main() {
    let message = b"hello world";
    let hash_code_length = 256;

    let hash = kupyna_hash(message, hash_code_length);

    println!("Hash: {:?}", hash);
}
```

### Running Tests

This implementation includes several unit tests to verify the correctness of the functions. You can run these tests using the following command:

```sh
cargo test
```

## Getting Started

I'm working on getting this read to go into a crate, or possibly merge it into an existing set of hashing functions. In the meantime, feel free to work with it directly.

### Installation

Clone the repository:
```sh
git clone https://github.com/jkoudys/kupyna.git
cd kupyna-rust
```

### Building the Project

Build the project using Cargo:
```sh
cargo build
```

### Running the Example

Run the example provided in the `main` function:
```sh
cargo run
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Contact

For any questions or suggestions, feel free to contact me at [josh@qaribou.com](mailto:josh@qaribou.com). Pull requests welcome!
