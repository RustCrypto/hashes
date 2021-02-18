#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2b_simd::blake2bp::blake2bp;

fuzz_target!(|data: &[u8]| {
    blake2bp(data);
});
