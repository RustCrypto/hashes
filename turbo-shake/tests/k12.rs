//! Test vectors for `k12` chaining values
use digest::{ExtendableOutput, Update};
use turbo_shake::{TurboShake128, TurboShake256};

const CHUNK_SIZE: usize = 1 << 13;
const CHUNK_DS: u8 = 0x0B;
const CHUNKS: usize = 32;

const KT128_CV_LEN: usize = 32;
const KT256_CV_LEN: usize = 64;

const KT128_CVS_LEN: usize = KT128_CV_LEN * CHUNKS;
const KT256_CVS_LEN: usize = KT256_CV_LEN * CHUNKS;

const DATA: &[u8] = &{
    let mut buf = [0u8; CHUNKS * CHUNK_SIZE];
    let mut i = 0;
    while i < CHUNKS {
        let mut j = 0;
        while j < CHUNK_SIZE {
            buf[i * CHUNK_SIZE + j] = (i + j) as u8;
            j += 1;
        }
        i += 1;
    }
    buf
};

const KT128_CVS: &[u8; KT128_CVS_LEN] = include_bytes!("data/kt128_cvs.bin");
const KT256_CVS: &[u8; KT256_CVS_LEN] = include_bytes!("data/kt256_cvs.bin");

#[test]
fn turboshake_kt128_cvs() {
    let mut cvs = [0u8; KT128_CVS_LEN];
    for (data_chunk, cv_dst) in DATA
        .chunks_exact(CHUNK_SIZE)
        .zip(cvs.chunks_exact_mut(KT128_CV_LEN))
    {
        let mut h = TurboShake128::<CHUNK_DS>::default();
        h.update(data_chunk);
        h.finalize_xof_into(cv_dst);
    }
    assert_eq!(&cvs, KT128_CVS);
}

#[test]
fn turboshake_kt256_cvs() {
    let mut cvs = [0u8; KT256_CVS_LEN];
    for (data_chunk, cv_dst) in DATA
        .chunks_exact(CHUNK_SIZE)
        .zip(cvs.chunks_exact_mut(KT256_CV_LEN))
    {
        let mut h = TurboShake256::<CHUNK_DS>::default();
        h.update(data_chunk);
        h.finalize_xof_into(cv_dst);
    }
    assert_eq!(&cvs, KT256_CVS);
}
