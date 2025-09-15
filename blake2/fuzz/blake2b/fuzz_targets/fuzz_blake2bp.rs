#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2::blake2bp::blake2bp;

fuzz_target!(|data: &[u8]| {
    blake2bp(data);
});
