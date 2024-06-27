
#[test]
fn full_test() {
    let message = b"Hello, World!".to_vec();
    let _message_length = 0;

    let _hash_code = crate::hash(message, None).unwrap();
}