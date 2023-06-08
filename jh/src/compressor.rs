#![allow(non_upper_case_globals)]

use core::ptr;
use digest::generic_array::{typenum::U64, GenericArray};
use hex_literal::hex;
use simd::{dispatch, vec128_storage, AndNot, Machine, Swap64, VZip, Vec2};

const E8_BITSLICE_ROUNDCONSTANT: [[u8; 32]; 42] = [
    hex!("72d5dea2df15f8677b84150ab723155781abd6904d5a87f64e9f4fc5c3d12b40"),
    hex!("ea983ae05c45fa9c03c5d29966b2999a660296b4f2bb538ab556141a88dba231"),
    hex!("03a35a5c9a190edb403fb20a87c144101c051980849e951d6f33ebad5ee7cddc"),
    hex!("10ba139202bf6b41dc786515f7bb27d00a2c813937aa78503f1abfd2410091d3"),
    hex!("422d5a0df6cc7e90dd629f9c92c097ce185ca70bc72b44acd1df65d663c6fc23"),
    hex!("976e6c039ee0b81a2105457e446ceca8eef103bb5d8e61fafd9697b294838197"),
    hex!("4a8e8537db03302f2a678d2dfb9f6a958afe7381f8b8696c8ac77246c07f4214"),
    hex!("c5f4158fbdc75ec475446fa78f11bb8052de75b7aee488bc82b8001e98a6a3f4"),
    hex!("8ef48f33a9a36315aa5f5624d5b7f989b6f1ed207c5ae0fd36cae95a06422c36"),
    hex!("ce2935434efe983d533af974739a4ba7d0f51f596f4e81860e9dad81afd85a9f"),
    hex!("a7050667ee34626a8b0b28be6eb9172747740726c680103fe0a07e6fc67e487b"),
    hex!("0d550aa54af8a4c091e3e79f978ef19e8676728150608dd47e9e5a41f3e5b062"),
    hex!("fc9f1fec4054207ae3e41a00cef4c9844fd794f59dfa95d8552e7e1124c354a5"),
    hex!("5bdf7228bdfe6e2878f57fe20fa5c4b205897cefee49d32e447e9385eb28597f"),
    hex!("705f6937b324314a5e8628f11dd6e465c71b770451b920e774fe43e823d4878a"),
    hex!("7d29e8a3927694f2ddcb7a099b30d9c11d1b30fb5bdc1be0da24494ff29c82bf"),
    hex!("a4e7ba31b470bfff0d324405def8bc483baefc3253bbd339459fc3c1e0298ba0"),
    hex!("e5c905fdf7ae090f947034124290f134a271b701e344ed95e93b8e364f2f984a"),
    hex!("88401d63a06cf61547c1444b8752afff7ebb4af1e20ac6304670b6c5cc6e8ce6"),
    hex!("a4d5a456bd4fca00da9d844bc83e18ae7357ce453064d1ade8a6ce68145c2567"),
    hex!("a3da8cf2cb0ee11633e906589a94999a1f60b220c26f847bd1ceac7fa0d18518"),
    hex!("32595ba18ddd19d3509a1cc0aaa5b4469f3d6367e4046bbaf6ca19ab0b56ee7e"),
    hex!("1fb179eaa9282174e9bdf7353b3651ee1d57ac5a7550d3763a46c2fea37d7001"),
    hex!("f735c1af98a4d84278edec209e6b677941836315ea3adba8fac33b4d32832c83"),
    hex!("a7403b1f1c2747f35940f034b72d769ae73e4e6cd2214ffdb8fd8d39dc5759ef"),
    hex!("8d9b0c492b49ebda5ba2d74968f3700d7d3baed07a8d5584f5a5e9f0e4f88e65"),
    hex!("a0b8a2f436103b530ca8079e753eec5a9168949256e8884f5bb05c55f8babc4c"),
    hex!("e3bb3b99f387947b75daf4d6726b1c5d64aeac28dc34b36d6c34a550b828db71"),
    hex!("f861e2f2108d512ae3db643359dd75fc1cacbcf143ce3fa267bbd13c02e843b0"),
    hex!("330a5bca8829a1757f34194db416535c923b94c30e794d1e797475d7b6eeaf3f"),
    hex!("eaa8d4f7be1a39215cf47e094c23275126a32453ba323cd244a3174a6da6d5ad"),
    hex!("b51d3ea6aff2c90883593d98916b3c564cf87ca17286604d46e23ecc086ec7f6"),
    hex!("2f9833b3b1bc765e2bd666a5efc4e62a06f4b6e8bec1d43674ee8215bcef2163"),
    hex!("fdc14e0df453c969a77d5ac4065858267ec1141606e0fa167e90af3d28639d3f"),
    hex!("d2c9f2e3009bd20c5faace30b7d40c30742a5116f2e032980deb30d8e3cef89a"),
    hex!("4bc59e7bb5f17992ff51e66e048668d39b234d57e6966731cce6a6f3170a7505"),
    hex!("b17681d913326cce3c175284f805a262f42bcbb378471547ff46548223936a48"),
    hex!("38df58074e5e6565f2fc7c89fc86508e31702e44d00bca86f04009a23078474e"),
    hex!("65a0ee39d1f73883f75ee937e42c3abd2197b2260113f86fa344edd1ef9fdee7"),
    hex!("8ba0df15762592d93c85f7f612dc42bed8a7ec7cab27b07e538d7ddaaa3ea8de"),
    hex!("aa25ce93bd0269d85af643fd1a7308f9c05fefda174a19a5974d66334cfd216a"),
    hex!("35b49831db411570ea1e0fbbedcd549b9ad063a151974072f6759dbf91476fe2"),
];

#[rustfmt::skip]
macro_rules! unroll7 {
    ($j:ident, $body:block) => {
        { const $j: usize = 0; $body }
        { const $j: usize = 1; $body }
        { const $j: usize = 2; $body }
        { const $j: usize = 3; $body }
        { const $j: usize = 4; $body }
        { const $j: usize = 5; $body }
        { const $j: usize = 6; $body }
    };
}

#[repr(C)]
#[derive(Copy, Clone)]
struct X8<M: Machine>(
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
    M::u128x1,
);
impl<M: Machine> X8<M> {
    #[inline(always)]
    fn zip(self) -> (M::u128x2, M::u128x2, M::u128x2, M::u128x2) {
        (
            [self.0, self.1].vzip(),
            [self.2, self.3].vzip(),
            [self.4, self.5].vzip(),
            [self.6, self.7].vzip(),
        )
    }
    #[inline(always)]
    fn unzip((a, b, c, d): (M::u128x2, M::u128x2, M::u128x2, M::u128x2)) -> Self {
        X8(
            a.extract(0),
            a.extract(1),
            b.extract(0),
            b.extract(1),
            c.extract(0),
            c.extract(1),
            d.extract(0),
            d.extract(1),
        )
    }
}

/// two Sboxes computed in parallel; each Sbox implements S0 and S1, selected by a constant bit
#[inline(always)]
fn ss<M: Machine>(state: X8<M>, mut k: M::u128x2) -> X8<M> {
    let mut m = state.zip();
    // TODO: replace ! with andnot ops?
    m.3 = !m.3;
    m.0 ^= m.2.andnot(k);
    k ^= m.0 & m.1;
    m.0 ^= m.3 & m.2;
    m.3 ^= m.1.andnot(m.2);
    m.1 ^= m.0 & m.2;
    m.2 ^= m.3.andnot(m.0);
    m.0 ^= m.1 | m.3;
    m.3 ^= m.1 & m.2;
    m.2 ^= k;
    m.1 ^= k & m.0;
    X8::unzip(m)
}

#[inline(always)]
fn l<M: Machine>(mut y: X8<M>) -> X8<M> {
    y.1 ^= y.2;
    y.3 ^= y.4;
    y.5 ^= y.6 ^ y.0;
    y.7 ^= y.0;
    y.0 ^= y.3;
    y.2 ^= y.5;
    y.4 ^= y.7 ^ y.1;
    y.6 ^= y.1;
    y
}

union X2Bytes<M: Machine> {
    x2: M::u128x2,
    bytes: [u8; 32],
}

#[inline(always)]
pub fn f8_impl<M: Machine>(mach: M, state: &mut [vec128_storage; 8], data: *const u8) {
    #[allow(clippy::cast_ptr_alignment)]
    let data = data as *const M::u128x1;
    let mut y = X8::<M>(
        mach.unpack(state[0]),
        mach.unpack(state[1]),
        mach.unpack(state[2]),
        mach.unpack(state[3]),
        mach.unpack(state[4]),
        mach.unpack(state[5]),
        mach.unpack(state[6]),
        mach.unpack(state[7]),
    );
    unsafe {
        y.0 ^= ptr::read_unaligned(data);
        y.1 ^= ptr::read_unaligned(data.offset(1));
        y.2 ^= ptr::read_unaligned(data.offset(2));
        y.3 ^= ptr::read_unaligned(data.offset(3));
    }
    for rc in E8_BITSLICE_ROUNDCONSTANT.chunks_exact(7) {
        unroll7!(j, {
            y = ss(y, unsafe { X2Bytes::<M> { bytes: rc[j] }.x2 });
            y = l(y);
            let f = match j {
                0 => M::u128x1::swap1,
                1 => M::u128x1::swap2,
                2 => M::u128x1::swap4,
                3 => M::u128x1::swap8,
                4 => M::u128x1::swap16,
                5 => M::u128x1::swap32,
                6 => M::u128x1::swap64,
                _ => unreachable!(),
            };
            y = X8(y.0, f(y.1), y.2, f(y.3), y.4, f(y.5), y.6, f(y.7));
        });
    }
    unsafe {
        y.4 ^= ptr::read_unaligned(data);
        y.5 ^= ptr::read_unaligned(data.offset(1));
        y.6 ^= ptr::read_unaligned(data.offset(2));
        y.7 ^= ptr::read_unaligned(data.offset(3));
    }
    *state = [
        y.0.into(),
        y.1.into(),
        y.2.into(),
        y.3.into(),
        y.4.into(),
        y.5.into(),
        y.6.into(),
        y.7.into(),
    ];
}

dispatch!(mach, M, {
    fn f8(state: &mut [vec128_storage; 8], data: *const u8) {
        f8_impl(mach, state, data);
    }
});

#[derive(Clone, Copy)]
pub union Compressor {
    cv: [vec128_storage; 8],
    bytes: [u8; 128],
}
impl Compressor {
    #[inline]
    pub fn new(bytes: [u8; 128]) -> Self {
        Compressor { bytes }
    }
    #[inline]
    pub fn input(&mut self, data: &GenericArray<u8, U64>) {
        f8(unsafe { &mut self.cv }, data.as_ptr());
    }
    #[inline]
    pub fn finalize(self) -> [u8; 128] {
        unsafe { self.bytes }
    }
}
