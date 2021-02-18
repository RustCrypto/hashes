#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2s_simd::blake2s;

fuzz_target!(|data: &[u8]| {
    blake2s(data);
});
