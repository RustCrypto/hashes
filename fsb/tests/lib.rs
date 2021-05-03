use hex_literal::hex;

use digest::Digest;
use fsb::*;

#[test]
fn main() {
    let msg_1 = b"hello";
    let msg_2 = b"The quick brown fox jumps over the lazy dog";
    let msg_3 = b"tiriri tralala potompompom";

    let mut hasher = Fsb160::new();
    hasher.update(msg_1);
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("6e8ce7998e4c46a4ca7c5e8f6498a5778140d14b")[..]
    );

    hasher = Fsb160::new();
    hasher.update(msg_2);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("a25f6e24c6fb67533f0a25233ac5cc09d5793e8a")[..]
    );

    hasher = Fsb160::new();
    hasher.update(msg_3);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("bfbd2f301a8ffbcfb60f3964d96d07e6569824f9")[..]
    );

    let mut hasher = Fsb224::new();
    hasher.update(msg_1);
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("5b04d5f3c350d00f8815f018d21a2e7289bc6993b4fa167976962537")[..]
    );

    hasher = Fsb224::new();
    hasher.update(msg_2);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("1dd28d92cad63335fcca4c64a5e1133ccaa8c3e6083ad15591280701")[..]
    );

    hasher = Fsb224::new();
    hasher.update(msg_3);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("bd9cc65169789ab20fbba27910a9f5323d0559f107eff3c55656dd23")[..]
    );

    let mut hasher = Fsb256::new();
    hasher.update(msg_1);
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("0f036dc3761aed2cba9de586a85976eedde6fa8f115c0190763decc02f28edbc")[..]
    );

    hasher = Fsb256::new();
    hasher.update(msg_2);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("a0751229aac5aeba6aeb1c0533988302e5084bb11029e7bb0ada7a653491df24")[..]
    );

    hasher = Fsb256::new();
    hasher.update(msg_3);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("f997ac523044618f2837407ad76bf41a194bb558cf50ea1c64b379be2f5f2b5e")[..]
    );

    let mut hasher = Fsb384::new();
    hasher.update(msg_1);
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("010d14a04da89df22685138b6b7795501ebdc109b6c714364126fcb46a0b570a9d714bc992455f8cf2099c8750cdb90b")[..]
    );

    hasher = Fsb384::new();
    hasher.update(msg_2);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("4983ecfa3930e3cf61ac4c82695c01a394016b39cf22b5d6dcba447ef8cbcda46ac341ccf5835f331fed0abe73e9bf1c")[..]
    );

    hasher = Fsb384::new();
    hasher.update(msg_3);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("0597e317f2a3f311db2485f0b8335607e6bcc6f918d07f6b0dc14bc044c558a9bcd0f5f346ad85bb043ff097f43f4f95")[..]
    );

    let mut hasher = Fsb512::new();
    hasher.update(msg_1);
    let result = hasher.finalize();

    assert_eq!(
        result[..],
        hex!("0c6bb476d9727b90a1f063435e8d611aacdc904e9680fe585b65442f2a3ac5043a3979ff252adf6cc9d34ef0b179a90ae2f2e8789f8797bff2426c90a58fb28b")[..]
    );

    hasher = Fsb512::new();
    hasher.update(msg_2);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("6f87b9dc051330bfb0dd7ad35c05d6a2040e9a6110b06886368934d6ae25694fd9790b1bf1086af9da4b15619609b688fa576376f136adbd3b5a51ae1a1f2158")[..]
    );

    hasher = Fsb512::new();
    hasher.update(msg_3);
    let result_1 = hasher.finalize();

    assert_eq!(
        result_1[..],
        hex!("7dd5255dafac0796df851d278eb70f554a539cc3dfdfe0a3d73e46df1ab51c029d3634db022fcd032ee8376ea777e34af118821fb1ff2b34b7378e517eacdc73")[..]
    );
}
