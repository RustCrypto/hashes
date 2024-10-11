# Kupyna Hash Function Implementation in Rust

## Overview

The Kupyna hash function is a cryptographic hash developed in Ukraine, designed for high security and efficiency. This implementation supports generating hash codes of various lengths.

## Authors

Joshua Koudys  
Email: [josh@qaribou.com](mailto:josh@qaribou.com)

Raj Singh Bisen  
Email: [typhoeusxoxo@gmail.com](mailto:typhoeusxoxo@gmail.com)

## Summary

Kupyna is a hash function standardized in Ukraine as DSTU 7564:2014. It is designed to provide a high level of security with a focus on robustness against various cryptographic attacks. The function supports different hash lengths, providing flexibility in usage depending on security requirements.

### Key Features of Kupyna:
- **High Security:** Resistant to known cryptographic attacks.
- **Efficiency:** Optimized for performance.
- **Flexibility:** Supports variable hash output lengths.

## Implementation Details

### TODO
Implement the excellent digest::Digest trait.
Work on streams of arbitrary size, so long as they have a known size by the end of them. Right
now it's just running on byte slices because it's easy.

### Usage

To compute the hash of a message using this implementation, you can call the `kupyna_hash` function with your message and desired hash length. Below is a basic usage example:

```rust
fn main() {
    let message = b"Hello, World!".to_vec();

    let kupyna = KupynaH::new(512);

    let hash_code = kupyna.hash(message, None).unwrap();

    println!("Hash: {:02X?}", hash_code);
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
