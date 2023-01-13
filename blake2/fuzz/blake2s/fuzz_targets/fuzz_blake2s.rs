#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2::blake2s::blake2s;

fuzz_target!(|data: &[u8]| {
    blake2s(data);
});
