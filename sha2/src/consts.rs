pub const STATE_LEN: usize = 8;

pub static H224: [u32; STATE_LEN] = [0xc1059ed8, 0x367cd507, 0x3070dd17,
                                     0xf70e5939, 0xffc00b31, 0x68581511,
                                     0x64f98fa7, 0xbefa4fa4];

pub static H256: [u32; STATE_LEN] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                     0xa54ff53a, 0x510e527f, 0x9b05688c,
                                     0x1f83d9ab, 0x5be0cd19];

pub static H384: [u64; STATE_LEN] = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                     0x9159015a3070dd17, 0x152fecd8f70e5939,
                                     0x67332667ffc00b31, 0x8eb44a8768581511,
                                     0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4];

pub static H512: [u64; STATE_LEN] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
                                     0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                     0x510e527fade682d1, 0x9b05688c2b3e6c1f,
                                     0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];

pub static H512_TRUNC_224: [u64; STATE_LEN] = [0x8c3d37c819544da2,
                                               0x73e1996689dcd4d6,
                                               0x1dfab7ae32ff9c82,
                                               0x679dd514582f9fcf,
                                               0x0f6d2b697bd44da8,
                                               0x77e36f7304c48942,
                                               0x3f9d85a86a1d36c8,
                                               0x1112e6ad91d692a1];

pub static H512_TRUNC_256: [u64; STATE_LEN] = [0x22312194fc2bf72c,
                                               0x9f555fa3c84c64c2,
                                               0x2393b86b6f53b151,
                                               0x963877195940eabd,
                                               0x96283ee2a88effe3,
                                               0xbe5e1e2553863992,
                                               0x2b0199fc2c85b8aa,
                                               0x0eb72ddc81c52ca2];
