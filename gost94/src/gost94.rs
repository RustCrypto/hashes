use digest::Digest;
use digest_buffer::DigestBuffer;
use generic_array::GenericArray;
use generic_array::typenum::U32;
use byte_tools::{read_u32v_le, read_u32_le, write_u32v_le, copy_memory};


pub const BLOCK_SIZE: usize = 32;

const C:Block = [0, 255, 0, 255, 0, 255, 0, 255, 255, 0, 255, 0, 255, 0,
255, 0, 0, 255, 255, 0, 255, 0, 0, 255, 255, 0, 0, 0, 255, 255, 0, 255];

pub type SBox = [[u8; 16]; 8];
type Block = [u8; 32];


fn sbox(a: u32, s: &SBox) -> u32 {
    let mut v = 0;
    for i in 0..8 {
        let shft = 4*i;
        let k = ((a & (0b1111u32 << shft) ) >> shft) as usize;
        v += (s[i][k] as u32) << shft;
    }
    v
}

fn g(a: u32, k: u32, s: &SBox) -> u32 {
    sbox(a.wrapping_add(k), s).rotate_left(11)
}

fn encrypt(msg: &mut [u8], key: Block, sbox: &SBox) {
    let mut k = [0u32; 8];
    let mut a = read_u32_le(&msg[0..4]);
    let mut b = read_u32_le(&msg[4..8]);
    read_u32v_le(&mut k, &key);

    for _ in 0..3 {
        for i in 0..8 {
            let t = b ^ g(a, k[i], sbox);
            b = a;
            a = t;
        }
    }
    for i in (0..8).rev() {
        let t = b ^ g(a, k[i], sbox);
        b = a;
        a = t;
    }
    write_u32v_le(msg, &[b, a]);
}

fn x(a: &Block, b: &Block) -> Block {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i]^b[i];
    }
    out
}

fn x_mut(a: &mut Block, b: &Block) {
    for i in 0..32 {
        a[i] ^= b[i];
    }
}


fn a(x: Block) -> Block {
    let mut out = [0; 32];
    for i in 0..24 {
        out[i] = x[i+8];
    }
    for i in 0..8 {
        out[24+i] = x[i]^x[i+8];
    }
    out
}

fn p(y: Block) -> Block {
    let mut out = [0; 32];
    for i in 0..4 {
        for k in 0..8 {
            out[i+4*k] = y[8*i+k];
        }
    }
    out
}


fn psi(block: &mut Block) {
    let mut out = [0u8; 32];
    copy_memory(&block[2..], &mut out[..30]);
    copy_memory(&block[..2], &mut out[30..]);

    for i in [1usize, 2, 3, 12, 15].iter() {
        out[30] ^= block[2*i];
        out[31] ^= block[2*i+1];
    }
    copy_memory(&out, block);
}

#[derive(Clone, Copy)]
struct Gost94State {
    s: SBox,
    h: Block,
    n: Block,
    sigma: Block,
}

impl Gost94State {
    fn shuffle(&mut self, m: &Block, s: &Block) {
        let mut res = [0u8; 32];
        copy_memory(s, &mut res);
        for _ in 0..12 {
            psi(&mut res);
        }
        x_mut(&mut res, m);
        psi(&mut res);
        x_mut(&mut self.h, &res);
        for _ in 0..61 {
            psi(&mut self.h);
        }
    }

    fn f(&mut self, m: &Block) {
        let mut s = [0u8; 32];
        copy_memory(&self.h, &mut s);
        let k = p(x(&self.h, m));
        encrypt(&mut s[0..8], k, &self.s);

        let u = a(self.h);
        let v = a(a(*m));
        let k = p(x(&u, &v));
        encrypt(&mut s[8..16], k, &self.s);

        let mut u = a(u);
        x_mut(&mut u, &C);
        let v = a(a(v));
        let k = p(x(&u, &v));
        encrypt(&mut s[16..24], k, &self.s);

        let u = a(u);
        let v = a(a(v));
        let k = p(x(&u, &v));
        encrypt(&mut s[24..32], k, &self.s);

        self.shuffle(m, &s);
    }

    fn update_sigma(&mut self, m: &[u8]) {
        let mut over = 0u16;
        for (a, b) in self.sigma.iter_mut().zip(m.iter()) {
            let res = (*a as u16) + (*b as u16) + over;
            *a = (res & 0xff) as u8;
            over = res >> 8;
        }
    }

    fn update_n(&mut self, m_len: u8) {
        let res = (self.n[0] as u16) + ((m_len as u16) << 3);
        self.n[0] = (res & 0xff) as u8;
        let mut over = res >> 8;

        for a in self.n.iter_mut().skip(1) {
            let res = (*a as u16) + over;
            *a = (res & 0xff) as u8;
            over = res >> 8;
            if over == 0 { return; }
        }
    }

    fn process_block(&mut self, block: &[u8], msg_len: u8) {
        let mut buf = [0u8; 32];
        copy_memory(block, &mut buf);
        self.f(&buf);
        self.update_n(msg_len);
        self.update_sigma(block);
    }
}

#[derive(Clone, Copy)]
pub struct Gost94 {
    buffer: DigestBuffer<U32>,
    state: Gost94State,
}

impl Gost94 {
    pub fn new(s: SBox, h: Block) -> Self {
        Gost94{
            buffer: Default::default(),
            state: Gost94State{
                s: s,
                h: h,
                n: [0; BLOCK_SIZE],
                sigma: [0; BLOCK_SIZE],
            }
        }
    }
}

impl Digest for Gost94 {
    type OutputSize = U32;
    type BlockSize = U32;

    fn input(&mut self, input: &[u8]) {
        let self_state = &mut self.state;
        self.buffer.input(input, |d: &[u8]| {
            self_state.process_block(d, 32);
        });
    }

    fn result(mut self) -> GenericArray<u8, Self::OutputSize> {
        let self_state = &mut self.state;
        let buf = self.buffer.current_buffer();

        if buf.len() != 0 {
            let mut block = [0u8; BLOCK_SIZE];
            copy_memory(&buf, &mut block[..buf.len()]);
            self_state.process_block(&block, buf.len() as u8);
        }

        let n = self_state.n;
        self_state.f(&n);

        let sigma = self_state.sigma;
        self_state.f(&sigma);

        let mut out = GenericArray::new();
        copy_memory(&self_state.h, &mut out);
        out
    }
}
