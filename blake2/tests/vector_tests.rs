//! The tests in this file run the standard set of test vectors from upstream:
//! https://github.com/BLAKE2/BLAKE2/blob/320c325437539ae91091ce62efec1913cd8093c2/testvectors/blake2-kat.json
//!
//! Currently those cover default hashing and keyed hashing in BLAKE2b and BLAKE2bp. But they don't
//! test the other associated data features, and they don't test any inputs longer than a couple
//! blocks.

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref TEST_CASES: Vec<TestCase> =
        serde_json::from_str(include_str!("../../.kat/blake2-kat.json")).unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
struct TestCase {
    hash: String,
    #[serde(rename = "in")]
    in_: String,
    key: String,
    out: String,
}

#[test]
fn blake2b_vectors() {
    let mut test_num = 0u64;
    for case in TEST_CASES.iter() {
        if &case.hash == "blake2b" {
            test_num += 1;
            println!("input {:?}, key {:?}", case.in_, case.key);

            let input_bytes = hex::decode(&case.in_).unwrap();
            let mut params = blake2::blake2b::Params::new();
            if !case.key.is_empty() {
                let key_bytes = hex::decode(&case.key).unwrap();
                params.key(&key_bytes);
            }

            // Assert the all-at-once result.
            assert_eq!(case.out, &*params.hash(&input_bytes).to_hex());

            // Assert the State result.
            let mut state = params.to_state();
            state.update(&input_bytes);
            assert_eq!(case.out, &*state.finalize().to_hex());
            assert_eq!(input_bytes.len() as u128, state.count());
        }
    }

    // Make sure we don't accidentally skip all the tests somehow. If the
    // number of test vectors changes in the future, we'll need to update this
    // count.
    assert_eq!(512, test_num);
}

#[test]
fn blake2bp_vectors() {
    let mut test_num = 0u64;
    for case in TEST_CASES.iter() {
        if &case.hash == "blake2bp" {
            test_num += 1;
            println!("input {:?}, key {:?}", case.in_, case.key);

            let input_bytes = hex::decode(&case.in_).unwrap();
            let mut params = blake2::blake2bp::Params::new();
            if !case.key.is_empty() {
                let key_bytes = hex::decode(&case.key).unwrap();
                params.key(&key_bytes);
            }

            // Assert the all-at-once result.
            assert_eq!(case.out, &*params.hash(&input_bytes).to_hex());

            // Assert the State result.
            let mut state = params.to_state();
            state.update(&input_bytes);
            assert_eq!(case.out, &*state.finalize().to_hex());
            assert_eq!(input_bytes.len() as u128, state.count());
        }
    }

    // Make sure we don't accidentally skip all the tests somehow. If the
    // number of test vectors changes in the future, we'll need to update this
    // count.
    assert_eq!(512, test_num);
}

#[test]
fn blake2s_vectors() {
    let mut test_num = 0u64;
    for case in TEST_CASES.iter() {
        if &case.hash == "blake2s" {
            test_num += 1;
            println!("input {:?}, key {:?}", case.in_, case.key);

            let input_bytes = hex::decode(&case.in_).unwrap();
            let mut params = blake2::blake2s::Params::new();
            if !case.key.is_empty() {
                let key_bytes = hex::decode(&case.key).unwrap();
                params.key(&key_bytes);
            }

            // Assert the all-at-once result.
            assert_eq!(case.out, &*params.hash(&input_bytes).to_hex());

            // Assert the State result.
            let mut state = params.to_state();
            state.update(&input_bytes);
            assert_eq!(case.out, &*state.finalize().to_hex());
            assert_eq!(input_bytes.len() as u64, state.count());
        }
    }

    // Make sure we don't accidentally skip all the tests somehow. If the
    // number of test vectors changes in the future, we'll need to update this
    // count.
    assert_eq!(512, test_num);
}

#[test]
fn blake2sp_vectors() {
    let mut test_num = 0u64;
    for case in TEST_CASES.iter() {
        if &case.hash == "blake2sp" {
            test_num += 1;
            println!("input {:?}, key {:?}", case.in_, case.key);

            let input_bytes = hex::decode(&case.in_).unwrap();
            let mut params = blake2::blake2sp::Params::new();
            if !case.key.is_empty() {
                let key_bytes = hex::decode(&case.key).unwrap();
                params.key(&key_bytes);
            }

            // Assert the all-at-once result.
            assert_eq!(case.out, &*params.hash(&input_bytes).to_hex());

            // Assert the State result.
            let mut state = params.to_state();
            state.update(&input_bytes);
            assert_eq!(case.out, &*state.finalize().to_hex());
            assert_eq!(input_bytes.len() as u64, state.count());
        }
    }

    // Make sure we don't accidentally skip all the tests somehow. If the
    // number of test vectors changes in the future, we'll need to update this
    // count.
    assert_eq!(512, test_num);
}

fn blake2x_test<F: Fn(&[u8], &[u8], u64) -> Vec<u8>, F2: Fn(&[u8], u64, usize) -> Vec<u8>>(
    h0_hasher: F,
    b2_hasher: F2,
    variant_hash_length: usize,
    variant_name: &str,
) {
    let mut test_num = 0u64;
    for case in TEST_CASES.iter() {
        if &case.hash == variant_name {
            test_num += 1;

            let input_bytes = hex::decode(&case.in_).unwrap();
            let key = if !case.key.is_empty() {
                hex::decode(&case.key).unwrap()
            } else {
                vec![]
            };

            let output_length = case.out.len() / 2;

            // BLAKE2X divides the underlying hash node_offset into two parts - node_offset
            // and xof_digest_length. This is the encoding of xof_digest_length in the
            // correct position in the node_offset.
            let combined_node_offset_xof_length = (output_length as u64) << 32;
            let h0 = h0_hasher(&input_bytes, &key, combined_node_offset_xof_length);

            let mut buf = vec![];
            let mut b2_hash_index = 0;
            while buf.len() < output_length {
                let hash_length = {
                    // Is this the last hash and the digest length doesn't divide the output
                    // length?
                    if output_length - buf.len() < variant_hash_length
                        && (output_length % variant_hash_length) != 0
                    {
                        output_length % variant_hash_length
                    } else {
                        variant_hash_length
                    }
                };

                let b2_out = b2_hasher(
                    &h0,
                    (b2_hash_index as u64) | combined_node_offset_xof_length,
                    hash_length,
                );
                buf.extend_from_slice(&b2_out);
                b2_hash_index += 1;
            }
            assert_eq!(case.out, hex::encode(&buf[..output_length]));
        }
    }

    // Make sure we don't accidentally skip all the tests somehow. If the
    // number of test vectors changes in the future, we'll need to update this
    // count.
    assert_eq!(512, test_num);
}

#[test]
fn blake2xs_vectors() {
    let blake2xs_h0_hasher =
        |input_bytes: &[u8], key: &[u8], combined_node_offset_xof_length: u64| -> Vec<u8> {
            let mut params = blake2::blake2s::Params::new();
            let h0 = params
                .key(key)
                .hash_length(32)
                .node_offset(combined_node_offset_xof_length)
                .hash(&input_bytes)
                .as_bytes()
                .to_vec();
            h0
        };
    let blake2xs_b2_hasher =
        |input_bytes: &[u8], combined_node_offset_xof_length: u64, hash_length: usize| -> Vec<u8> {
            let mut params = blake2::blake2s::Params::new();
            let b2_out = params
                .hash_length(hash_length)
                .max_leaf_length(32)
                .inner_hash_length(32)
                .fanout(0)
                .max_depth(0)
                .node_offset(combined_node_offset_xof_length)
                .hash(&input_bytes)
                .as_bytes()
                .to_vec();
            b2_out
        };

    blake2x_test(blake2xs_h0_hasher, blake2xs_b2_hasher, 32, "blake2xs");
}

#[test]
fn blake2xb_vectors() {
    let blake2xb_h0_hasher =
        |input_bytes: &[u8], key: &[u8], combined_node_offset_xof_length: u64| -> Vec<u8> {
            let mut params = blake2::blake2b::Params::new();
            let h0 = params
                .key(key)
                .hash_length(64)
                .node_offset(combined_node_offset_xof_length)
                .hash(&input_bytes)
                .as_bytes()
                .to_vec();
            h0
        };
    let blake2xb_b2_hasher =
        |input_bytes: &[u8], combined_node_offset_xof_length: u64, hash_length: usize| -> Vec<u8> {
            let mut params = blake2::blake2b::Params::new();
            let b2_out = params
                .hash_length(hash_length)
                .max_leaf_length(64)
                .inner_hash_length(64)
                .fanout(0)
                .max_depth(0)
                .node_offset(combined_node_offset_xof_length)
                .hash(&input_bytes)
                .as_bytes()
                .to_vec();
            b2_out
        };

    blake2x_test(blake2xb_h0_hasher, blake2xb_b2_hasher, 64, "blake2xb");
}
