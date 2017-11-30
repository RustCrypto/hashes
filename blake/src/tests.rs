use super::*;
use digest::Digest;

const OUT224_0X1: &[u8] = hex!("4504cb0314fb2a4f7a692e696e487912fe3f2468fe312c73a5278ec5");
const OUT224_0X72: &[u8] = hex!("f5aa00dd1cb847e3140372af7b5c46b4888d82c8c0a917913cfb5d04");

#[test]
fn test224_0x1() {
    let out = Blake224::digest(&[0; 1]);
    assert_eq!(&out[..], &OUT224_0X1[..]);
}

#[test]
fn test224_0x72() {
    let out = Blake224::digest(&[0; 72]);
    assert_eq!(&out[..], &OUT224_0X72[..]);
}

#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT256_0X1: &[u8] =
    hex!("0ce8d4ef4dd7cd8d62dfded9d4edb0a774ae6a41929a74da23109e8f11139c87");
#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT256_0X72: &[u8] =
    hex!("d419bad32d504fb7d44d460c42c5593fe544fa4c135dec31e21bd9abdcc22d41");

#[test]
fn test256_0x1() {
    let out = Blake256::digest(&[0; 1]);
    assert_eq!(&out[..], &OUT256_0X1[..]);
}

#[test]
fn test256_0x72() {
    let out = Blake256::digest(&[0; 72]);
    assert_eq!(&out[..], &OUT256_0X72[..]);
}

#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT384_0X1: &[u8] = hex!("10281f67e135e90ae8e882251a355510a719367ad70227b1
                                37343e1bc122015c29391e8545b5272d13a7c2879da3d807");
#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT384_0X144: &[u8] = hex!("0b9845dd429566cdab772ba195d271effe2d0211f16991d7
                                    66ba749447c5cde569780b2daa66c4b224a2ec2e5d09174c");

#[test]
fn test384_0x1() {
    let out = Blake384::digest(&[0; 1]);
    assert_eq!(&out[..], &OUT384_0X1[..]);
}

#[test]
fn test384_0x144() {
    let out = Blake384::digest(&[0; 144]);
    assert_eq!(&out[..], &OUT384_0X144[..]);
}

#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT512_0X1: &[u8] =
    hex!("97961587f6d970faba6d2478045de6d1fabd09b61ae50932054d52bc29d31be4
            ff9102b9f69e2bbdb83be13d4b9c06091e5fa0b48bd081b634058be0ec49beb3");
#[cfg_attr(rustfmt, rustfmt_skip)]
const OUT512_0X144: &[u8] =
    hex!("313717d608e9cf758dcb1eb0f0c3cf9fC150b2d500fb33f51c52afc99d358a2f
            1374b8a38bba7974e7f6ef79cab16f22CE1e649d6e01ad9589c213045d545dde");

#[test]
fn test512_0x1() {
    let out = Blake512::digest(&[0; 1]);
    assert_eq!(&out[..], &OUT512_0X1[..]);
}

#[test]
fn test512_0x144() {
    let out = Blake512::digest(&[0; 144]);
    assert_eq!(&out[..], &OUT512_0X144[..]);
}
