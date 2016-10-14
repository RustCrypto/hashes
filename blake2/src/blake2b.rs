use byte_tools::{copy_memory, read_u64v_le, write_u64v_le,
    write_u32_le, write_u64_le};
use crypto_ops::secure_memset;
use digest::Digest;
// use crypto_mac::{Mac, MacResult512};
use generic_array::{GenericArray, ArrayLength};
// use generic_array::typenum::{U64, Unsigned};
use generic_array::typenum::U64;

use consts::BLAKE2B_IV as IV;
use consts::{SIGMA, BLAKE2B_BLOCKBYTES, BLAKE2B_OUTBYTES, BLAKE2B_KEYBYTES,
             BLAKE2B_SALTBYTES, BLAKE2B_PERSONALBYTES};

use core::marker::PhantomData;

#[derive(Copy)]
pub struct Blake2b<N> where N: ArrayLength<u8> + Copy {
    h: [u64; 8],
    t: [u64; 2],
    f: [u64; 2],
    buf: [u8; 2*BLAKE2B_BLOCKBYTES],
    buflen: usize,
    key: [u8; BLAKE2B_KEYBYTES],
    key_length: u8,
    last_node: u8,
    param: Blake2bParam,
    // Phantom data to tie digest length to this struct
    phantom: PhantomData<N>,
}

pub type Blake2b512 = Blake2b<U64>;

impl<N> Clone for Blake2b<N> where N: ArrayLength<u8> + Copy  {
    fn clone(&self) -> Blake2b<N> { *self }
}

#[derive(Copy, Clone)]
struct Blake2bParam {
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u64,
    node_depth: u8,
    inner_length: u8,
    reserved: [u8; 14],
    salt: [u8; BLAKE2B_SALTBYTES],
    personal: [u8; BLAKE2B_PERSONALBYTES],
}

macro_rules! G( ($r:expr, $i:expr, $a:expr, $b:expr, $c:expr, $d:expr, $m:expr) => ({
    $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2*$i+0]]);
    $d = ($d ^ $a).rotate_right(32);
    $c = $c.wrapping_add($d);
    $b = ($b ^ $c).rotate_right(24);
    $a = $a.wrapping_add($b).wrapping_add($m[SIGMA[$r][2*$i+1]]);
    $d = ($d ^ $a).rotate_right(16);
    $c = $c .wrapping_add($d);
    $b = ($b ^ $c).rotate_right(63);
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

impl<N> Blake2b<N> where N: ArrayLength<u8> + Copy  {
    fn set_lastnode(&mut self) {
        self.f[1] = 0xFFFFFFFFFFFFFFFF;
    }

    fn set_lastblock(&mut self) {
        if self.last_node!=0 {
            self.set_lastnode();
        }
        self.f[0] = 0xFFFFFFFFFFFFFFFF;
    }

    fn increment_counter(&mut self, inc : u64) {
        self.t[0] += inc;
        self.t[1] += if self.t[0] < inc { 1 } else { 0 };
    }

    fn apply_param(&mut self) {
        let mut param_bytes = [0u8; 64];

        param_bytes[0] = N::to_u8();
        param_bytes[1] = self.param.key_length;
        param_bytes[2] = self.param.fanout;
        param_bytes[3] = self.param.depth;
        write_u32_le(&mut param_bytes[4..8], self.param.leaf_length);
        write_u64_le(&mut param_bytes[8..16], self.param.node_offset);
        param_bytes[16] = self.param.node_depth;
        param_bytes[17] = self.param.inner_length;
        param_bytes[18..32].copy_from_slice(&self.param.reserved);
        param_bytes[32..48].copy_from_slice(&self.param.salt);
        param_bytes[48..].copy_from_slice(&self.param.personal);

        let mut param_words : [u64; 8] = [0; 8];
        read_u64v_le(&mut param_words, &param_bytes);
        for (h, param_word) in self.h.iter_mut().zip(param_words.iter()) {
            *h = *h ^ *param_word;
        }
    }

    // init xors IV with input parameter block
    fn init(param: Blake2bParam, key: &[u8]) -> Blake2b<N> {
        assert!(key.len() <= BLAKE2B_KEYBYTES);
        let mut b = Blake2b {
            h: IV,
            t: [0,0],
            f: [0,0],
            buf: [0; 2*BLAKE2B_BLOCKBYTES],
            buflen: 0,
            last_node: 0,
            key: [0; BLAKE2B_KEYBYTES],
            key_length: key.len() as u8,
            param: param,
            phantom: PhantomData,
        };
        copy_memory(key, &mut b.key);
        b.apply_param();
        b
    }

    fn apply_key(&mut self) {
        let mut block : [u8; BLAKE2B_BLOCKBYTES] = [0; BLAKE2B_BLOCKBYTES];
        copy_memory(&self.key[..self.key_length as usize], &mut block);
        self.update(&block);
        secure_memset(&mut block[..], 0);
    }

    pub fn new_keyed(key: &[u8] ) -> Blake2b<N> {
        assert!(N::to_usize() > 0 && N::to_usize() <= BLAKE2B_OUTBYTES);
        assert!(key.len() > 0 && key.len() <= BLAKE2B_KEYBYTES);

        let param = Blake2bParam {
            key_length: key.len() as u8,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            reserved: [0; 14],
            salt: [0; BLAKE2B_SALTBYTES],
            personal: [0; BLAKE2B_PERSONALBYTES],
        };

        let mut b = Blake2b::init(param, key);
        b.apply_key();
        b
    }

    fn compress(&mut self) {
        let mut ms: [u64; 16] = [0; 16];
        let mut vs: [u64; 16] = [0; 16];

        read_u64v_le(&mut ms, &self.buf[0..BLAKE2B_BLOCKBYTES]);

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
        round!( 10, vs, ms );
        round!( 11, vs, ms );

        let iter = self.h.iter_mut().zip(vs[0..8].iter().zip(vs[8..16].iter()));
        for (h_elem, (v_low, v_high)) in iter {
            *h_elem = *h_elem ^ *v_low ^ *v_high;
        }
    }


    fn update(&mut self, input: &[u8]) {
        let mut input = input;
        while input.len() > 0 {
            let left = self.buflen;
            let fill = 2 * BLAKE2B_BLOCKBYTES - left;

            if input.len() > fill {
                copy_memory(&input[0..fill], &mut self.buf[left..]); // Fill buffer
                self.buflen += fill;
                self.increment_counter( BLAKE2B_BLOCKBYTES as u64);
                self.compress();

                let mut halves = self.buf.chunks_mut(BLAKE2B_BLOCKBYTES);
                let first_half = halves.next().unwrap();
                let second_half = halves.next().unwrap();
                copy_memory(second_half, first_half);

                self.buflen -= BLAKE2B_BLOCKBYTES;
                input = &input[fill..input.len()];
            } else { // inlen <= fill
                copy_memory(input, &mut self.buf[left..]);
                self.buflen += input.len();
                break;
            }
        }
    }

    fn finalize(mut self) -> GenericArray<u8, N> {
        if self.buflen > BLAKE2B_BLOCKBYTES {
            self.increment_counter(BLAKE2B_BLOCKBYTES as u64);
            self.compress();
            self.buflen -= BLAKE2B_BLOCKBYTES;

            let mut halves = self.buf.chunks_mut(BLAKE2B_BLOCKBYTES);
            let first_half = halves.next().unwrap();
            let second_half = halves.next().unwrap();
            copy_memory(second_half, first_half);
        }

        let incby = self.buflen as u64;
        self.increment_counter(incby);
        self.set_lastblock();
        for b in self.buf[self.buflen..].iter_mut() {
            *b = 0;
        }
        self.compress();

        write_u64v_le(&mut self.buf[0..64], &self.h);

        let mut out = GenericArray::new();
        copy_memory(&self.buf[..N::to_usize()], &mut out);
        out
    }
}

impl<N> Digest for Blake2b<N> where N: ArrayLength<u8> + Copy {
    type R = N;
    type B = U64;

    fn new() -> Blake2b<N> {
        assert!(N::to_usize() > 0 && N::to_usize() <= BLAKE2B_OUTBYTES);
        let param = Blake2bParam {
            key_length: 0,
            fanout: 1,
            depth: 1,
            leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_length: 0,
            reserved: [0; 14],
            salt: [0; BLAKE2B_SALTBYTES],
            personal: [0; BLAKE2B_PERSONALBYTES],
        };

        Blake2b::init(param, &[])
    }

    fn input(&mut self, input: &[u8]) { self.update(input); }

    fn result(self) -> GenericArray<u8, Self::R> { self.finalize() }
}

/*
impl<N> Mac for Blake2b<N> {
    type R = N;

    fn input(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn result(&mut self) -> MacResult<N> {
        MacResult::new(self.result())
    }
}
*/