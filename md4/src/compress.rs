use core::num::Wrapping;

type Wu32 = Wrapping<u32>;

const K1: Wu32 = Wrapping(0x5A82_7999);
const K2: Wu32 = Wrapping(0x6ED9_EBA1);

pub(crate) fn compress(state: &mut [u32; 4], input: &[u8; 64]) {
    fn f(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        z ^ (x & (y ^ z))
    }

    fn g(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: Wu32, y: Wu32, z: Wu32) -> Wu32 {
        x ^ y ^ z
    }

    fn op<F>(f: F, a: Wu32, b: Wu32, c: Wu32, d: Wu32, k: Wu32, s: u32) -> Wu32
    where
        F: Fn(Wu32, Wu32, Wu32) -> Wu32,
    {
        let t = a + f(b, c, d) + k;
        Wrapping(t.0.rotate_left(s))
    }

    let [mut a, mut b, mut c, mut d] = state.map(Wrapping);

    // load block to data
    let mut data = [Wrapping(0u32); 16];
    for (o, chunk) in data.iter_mut().zip(input.chunks_exact(4)) {
        *o = Wrapping(u32::from_le_bytes(chunk.try_into().unwrap()));
    }

    // round 1
    for &i in &[0, 4, 8, 12] {
        a = op(f, a, b, c, d, data[i], 3);
        d = op(f, d, a, b, c, data[i + 1], 7);
        c = op(f, c, d, a, b, data[i + 2], 11);
        b = op(f, b, c, d, a, data[i + 3], 19);
    }

    // round 2
    for &i in &[0, 1, 2, 3] {
        a = op(g, a, b, c, d, data[i] + K1, 3);
        d = op(g, d, a, b, c, data[i + 4] + K1, 5);
        c = op(g, c, d, a, b, data[i + 8] + K1, 9);
        b = op(g, b, c, d, a, data[i + 12] + K1, 13);
    }

    // round 3
    for &i in &[0, 2, 1, 3] {
        a = op(h, a, b, c, d, data[i] + K2, 3);
        d = op(h, d, a, b, c, data[i + 8] + K2, 9);
        c = op(h, c, d, a, b, data[i + 4] + K2, 11);
        b = op(h, b, c, d, a, data[i + 12] + K2, 15);
    }

    state[0] = state[0].wrapping_add(a.0);
    state[1] = state[1].wrapping_add(b.0);
    state[2] = state[2].wrapping_add(c.0);
    state[3] = state[3].wrapping_add(d.0);
}
