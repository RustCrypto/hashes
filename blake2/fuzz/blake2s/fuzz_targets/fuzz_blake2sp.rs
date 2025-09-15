#![no_main]
use libfuzzer_sys::fuzz_target;

use blake2::blake2sp::blake2sp;

fuzz_target!(|data: &[u8]| {
    blake2sp(data);
});
