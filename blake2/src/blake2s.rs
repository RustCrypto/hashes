use byte_tools::{copy_memory, read_u32v_le, write_u32v_le, write_u32_le};
use crypto_ops::secure_memset;
use digest::Digest;
//use crypto_mac::{Mac, MacResult256};
use generic_array::{GenericArray, ArrayLength};
// use generic_array::typenum::{U32, Unsigned};
use generic_array::typenum::{U32, U128};

use consts::BLAKE2S_IV as IV;
use consts::{SIGMA, BLAKE2S_BLOCKBYTES, BLAKE2S_OUTBYTES, BLAKE2S_KEYBYTES,
             BLAKE2S_SALTBYTES, BLAKE2S_PERSONALBYTES};

use core::marker::PhantomData;

#[derive(Copy, Clone)]
pub struct Blake2s<N> where N: ArrayLength<u8> + Copy {
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buf: GenericArray<u8, U128>,
    buflen: usize,
    key: [u8; BLAKE2S_KEYBYTES],
    key_length: u8,
    last_node: u8,
    param: Blake2sParam,
    // Phantom data to tie digest length to this struct
    phantom: PhantomData<N>,
}

pub type Blake2s256 = Blake2s<U32>;

#[derive(Copy, Clone)]
struct Blake2sParam {
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: [u8; 6],
    node_depth: u8,
    inner_length: u8,
    salt: [u8; BLAKE2S_SALTBYTES],
    personal: [u8; BLAKE2S_PERSONALBYTES],
}

macro_rules! G( ($r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $m:expr) => ({
    $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2*$i+0]]);
    $d = ($d ^ $a).rotate_right(16);
    $c = $c.wrapping_add($d);
    $b = ($b ^ $c).rotate_right(12);
    $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2*$i+1]]);
    $d = ($d ^ $a).rotate_right(8);
    $c = $c.wrapping_add($d);
    $b = ($b ^ $c).rotate_right(7);
}));

macro_rules! round( ($r:expr, $v:expr, $m:expr) => ( {
    G!($r,0,$v[ 0],$v[ 4],$v[ 8],$v[12], $m);
    G!($r,1,$v[ 1],$v[ 5],$v[ 9],$v[13], $m);
    G!($r,2,$v[ 2],$v[ 6],$v[10],$v[14], $m);
    G!($r,3,$v[ 3],$v[ 7],$v[11],$v[15], $m);
    G!($r,4,$v[ 0],$v[ 5],$v[10],$v[15], $m);
    G!($r,5,$v[ 1],$v[ 6],$v[11],$v[12], $m);
    G!($r,6,$v[ 2],$v[ 7],$v[ 8],$v[13], $m);
    G!($r,7,$v[ 3],$v[ 4],$v[ 9],$v[14], $m);
  }
));

impl<N> Blake2s<N> where N: ArrayLength<u8> + Copy {
    pub fn new() -> Blake2s<N> {
        assert!(N::to_usize() > 0 && N::to_usize() <= BLAKE2S_OUTBYTES);
        let default_param = Blake2sParam {
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: [0; 6],
            node_depth: 0,
            inner_length: 0,
            salt: [0; BLAKE2S_SALTBYTES],
            personal: [0; BLAKE2S_PERSONALBYTES],
        };
        Blake2s::init(default_param, &[])
    }

    fn set_lastnode(&mut self) {
        self.f[1] = 0xFFFFFFFF;
    }

    fn set_lastblock(&mut self) {
        if self.last_node!=0 {
            self.set_lastnode();
        }
        self.f[0] = 0xFFFFFFFF;
    }

    fn increment_counter(&mut self, inc : u32) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }

    fn apply_param(&mut self) {
        let mut param_bytes = [0u8; 32];

        param_bytes[0] = N::to_u8();
        param_bytes[1] = self.param.key_length;
        param_bytes[2] = self.param.fanout;
        param_bytes[3] = self.param.depth;
        write_u32_le(&mut param_bytes[4..8], self.param.leaf_length);
        param_bytes[8..14].copy_from_slice(&self.param.node_offset);
        param_bytes[15] = self.param.node_depth;
        param_bytes[16] = self.param.inner_length;
        param_bytes[16..24].copy_from_slice(&self.param.salt);
        param_bytes[24..].copy_from_slice(&self.param.personal);

        let mut param_words : [u32; 8] = [0; 8];
        read_u32v_le(&mut param_words, &param_bytes);
        for (h, param_word) in self.h.iter_mut().zip(param_words.iter()) {
            *h = *h ^ *param_word;
        }
    }

    // init xors IV with input parameter block
    fn init( param: Blake2sParam, key: &[u8] ) -> Blake2s<N> {
        assert!(key.len() <= BLAKE2S_KEYBYTES);
        let mut b = Blake2s {
            h: IV,
            t: [0,0],
            f: [0,0],
            buf: GenericArray::new(),
            buflen: 0,
            last_node: 0,
            key: [0; BLAKE2S_KEYBYTES],
            key_length: key.len() as u8,
            param: param,
            phantom: PhantomData,
        };
        copy_memory(key, &mut b.key);
        b.apply_param();
        b
    }

    fn apply_key(&mut self) {
        let mut block : [u8; BLAKE2S_BLOCKBYTES] = [0; BLAKE2S_BLOCKBYTES];
        copy_memory(&self.key[..self.key_length as usize], &mut block);
        self.update(&block);
        secure_memset(&mut block[..], 0);
    }

    pub fn new_keyed(key: &[u8] ) -> Blake2s<N> {
        assert!(N::to_usize() > 0 && N::to_usize() <= BLAKE2S_OUTBYTES);
        assert!(key.len() > 0 && key.len() <= BLAKE2S_KEYBYTES);

        let param = Blake2sParam {
            key_length: key.len() as u8,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: [0; 6],
            node_depth: 0,
            inner_length: 0,
            salt: [0; BLAKE2S_SALTBYTES],
            personal: [0; BLAKE2S_PERSONALBYTES],
        };

        let mut b = Blake2s::init(param, key);
        b.apply_key();
        b
    }

    fn compress(&mut self) {
        let mut ms: [u32; 16] = [0; 16];
        let mut vs: [u32; 16] = [0; 16];

        read_u32v_le(&mut ms, &self.buf[0..BLAKE2S_BLOCKBYTES]);

        for (v, h) in vs.iter_mut().zip(self.h.iter()) {
            *v = *h;
        }

        vs[ 8] = IV[0];
        vs[ 9] = IV[1];
        vs[10] = IV[2];
        vs[11] = IV[3];
        vs[12] = self.t[0] ^ IV[4];
        vs[13] = self.t[1] ^ IV[5];
        vs[14] = self.f[0] ^ IV[6];
        vs[15] = self.f[1] ^ IV[7];
        round!(  0, vs, ms );
        round!(  1, vs, ms );
        round!(  2, vs, ms );
        round!(  3, vs, ms );
        round!(  4, vs, ms );
        round!(  5, vs, ms );
        round!(  6, vs, ms );
        round!(  7, vs, ms );
        round!(  8, vs, ms );
        round!(  9, vs, ms );

        for (h_elem, (v_low, v_high)) in self.h.iter_mut().zip( vs[0..8].iter().zip(vs[8..16].iter()) ) {
            *h_elem = *h_elem ^ *v_low ^ *v_high;
        }
    }

    fn update( &mut self, mut input: &[u8] ) {
        while input.len() > 0 {
            let left = self.buflen;
            let fill = 2 * BLAKE2S_BLOCKBYTES - left;

            if input.len() > fill {
                copy_memory(&input[0..fill], &mut self.buf[left..]); // Fill buffer
                self.buflen += fill;
                self.increment_counter( BLAKE2S_BLOCKBYTES as u32);
                self.compress();

                let mut halves = self.buf.chunks_mut(BLAKE2S_BLOCKBYTES);
                let first_half = halves.next().unwrap();
                let second_half = halves.next().unwrap();
                copy_memory(second_half, first_half);

                self.buflen -= BLAKE2S_BLOCKBYTES;
                input = &input[fill..input.len()];
            } else { // inlen <= fill
                copy_memory(input, &mut self.buf[left..]);
                self.buflen += input.len();
                break;
            }
        }
    }

    fn finalize(mut self) -> GenericArray<u8, N> {
        if self.buflen > BLAKE2S_BLOCKBYTES {
            self.increment_counter(BLAKE2S_BLOCKBYTES as u32);
            self.compress();
            self.buflen -= BLAKE2S_BLOCKBYTES;

            let mut halves = self.buf.chunks_mut(BLAKE2S_BLOCKBYTES);
            let first_half = halves.next().unwrap();
            let second_half = halves.next().unwrap();
            copy_memory(second_half, first_half);
        }

        let incby = self.buflen as u32;
        self.increment_counter(incby);
        self.set_lastblock();
        for b in self.buf[self.buflen..].iter_mut() {
            *b = 0;
        }
        self.compress();

        write_u32v_le(&mut self.buf[0..32], &self.h);

        let mut out = GenericArray::new();
        copy_memory(&self.buf[..N::to_usize()], &mut out);
        out
    }
}

impl<N> Default for Blake2s<N> where N: ArrayLength<u8> + Copy {
    fn default() -> Self { Self::new() }
}

impl<N> Digest for Blake2s<N> where N: ArrayLength<u8> + Copy {
    type OutputSize = N;
    type BlockSize = U32;

    fn input(&mut self, input: &[u8]) { self.update(input); }

    fn result(self) -> GenericArray<u8, Self::OutputSize> { self.finalize() }
}

/*
impl<N> Mac for Blake2s<N> {
    type R = N;

    fn input(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn result(&mut self) -> MacResult<N> {
        MacResult::new(self.result())
    }
}
*/