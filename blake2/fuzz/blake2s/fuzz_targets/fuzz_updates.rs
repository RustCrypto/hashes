#![no_main]
use libfuzzer_sys::{fuzz_target, arbitrary};

use blake2s_simd::{OUTBYTES, KEYBYTES, Params, PERSONALBYTES};

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Wrapper {
    hash_length: usize,
    key: Vec<u8>,
    personal: Vec<u8>,
    updates: Vec<Vec<u8>>,
}

fuzz_target!(|wrap: Wrapper| {
    if wrap.personal.len() > PERSONALBYTES {
        return;
    }
    if wrap.key.len() > KEYBYTES {
        return;
    }
    if 1 > wrap.hash_length || wrap.hash_length > OUTBYTES {
        return;
    }

    let mut hasher = Params::new()
        .hash_length(wrap.hash_length)
        .key(&wrap.key)
        .personal(&wrap.personal)
        .to_state();

    for update in wrap.updates {
        hasher.update(&update);
    }
    hasher.finalize();
});
