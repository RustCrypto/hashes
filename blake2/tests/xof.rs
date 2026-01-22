use blake2::blake2xb;
use digest::XofReader;
use hex_literal::hex;

#[test]
fn blake2bx() {
    let seed = hex!(
        "7201a801c4f9957c7665c2fd42761f5d"
        "a6c05551f15c2153788ba70d9560d7ee"
    );
    let mut b = blake2xb(&seed[..]);

    let expected = hex!(
        "4bd410911bf5dcb1992eb723835498da"
        "bf58ce3482393c2bd2aa3b79c4e22cb8"
        "06e631652e2aff3c339864512eddc1e0"
        "2717b2ebd499a6e9e1b8967d230054a4"
        "1658a3f4fe04b0629fc8e69f6bf51de7"
        "59090ce54d82c0dadac921a33f18b1b6"
        "be8e9b124d46f26b9cb0dbecae21f504"
        "886bc0753e9e62d498dfb018b34a14d5"
        "fceef4c0d978e1da27a071564d7ebd56"
        "fd092765199e1791ddad7b601d26ce39"
        "2639ad17c2eb607f9e82782e5f725d19"
        "69b6b4f08b919ff4c7f41c04a9b8ee08"
    );
    let mut buf = [0; 64 * 3];
    b.read(&mut buf);
    assert_eq!(expected, buf);
}
