#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2::blake2b::blake2b;

fuzz_target!(|data: &[u8]| {
    blake2b(data);
});
