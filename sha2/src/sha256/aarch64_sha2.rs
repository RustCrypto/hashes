//! SHA-256 `aarch64` backend.
#![allow(unsafe_op_in_unsafe_fn)]

// Implementation adapted from mbedtls.

use core::arch::aarch64::*;

use crate::consts::K32;

cpufeatures::new!(sha2_hwcap, "sha2");

pub(super) fn compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // TODO: Replace with https://github.com/rust-lang/rfcs/pull/2725
    // after stabilization
    if sha2_hwcap::get() {
        unsafe { sha256_compress(state, blocks) }
    } else {
        super::soft::compress(state, blocks);
    }
}

#[target_feature(enable = "sha2")]
unsafe fn sha256_compress(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
    // SAFETY: Requires the sha2 feature.

    // Load state into vectors.
    let mut abcd = vld1q_u32(state[0..4].as_ptr());
    let mut efgh = vld1q_u32(state[4..8].as_ptr());

    // Iterate through the message blocks.
    for block in blocks {
        // Keep original state values.
        let abcd_orig = abcd;
        let efgh_orig = efgh;

        // Load the message block into vectors, assuming little endianness.
        let mut s0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[0..16].as_ptr())));
        let mut s1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[16..32].as_ptr())));
        let mut s2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[32..48].as_ptr())));
        let mut s3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block[48..64].as_ptr())));

        // Rounds 0 to 3
        let mut tmp = vaddq_u32(s0, vld1q_u32(&K32[0]));
        let mut abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds 4 to 7
        tmp = vaddq_u32(s1, vld1q_u32(&K32[4]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds 8 to 11
        tmp = vaddq_u32(s2, vld1q_u32(&K32[8]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        // Rounds 12 to 15
        tmp = vaddq_u32(s3, vld1q_u32(&K32[12]));
        abcd_prev = abcd;
        abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
        efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

        for t in (16..64).step_by(16) {
            // Rounds t to t + 3
            s0 = vsha256su1q_u32(vsha256su0q_u32(s0, s1), s2, s3);
            tmp = vaddq_u32(s0, vld1q_u32(&K32[t]));
            abcd_prev = abcd;
            abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

            // Rounds t + 4 to t + 7
            s1 = vsha256su1q_u32(vsha256su0q_u32(s1, s2), s3, s0);
            tmp = vaddq_u32(s1, vld1q_u32(&K32[t + 4]));
            abcd_prev = abcd;
            abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

            // Rounds t + 8 to t + 11
            s2 = vsha256su1q_u32(vsha256su0q_u32(s2, s3), s0, s1);
            tmp = vaddq_u32(s2, vld1q_u32(&K32[t + 8]));
            abcd_prev = abcd;
            abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);

            // Rounds t + 12 to t + 15
            s3 = vsha256su1q_u32(vsha256su0q_u32(s3, s0), s1, s2);
            tmp = vaddq_u32(s3, vld1q_u32(&K32[t + 12]));
            abcd_prev = abcd;
            abcd = vsha256hq_u32(abcd_prev, efgh, tmp);
            efgh = vsha256h2q_u32(efgh, abcd_prev, tmp);
        }

        // Add the block-specific state to the original state.
        abcd = vaddq_u32(abcd, abcd_orig);
        efgh = vaddq_u32(efgh, efgh_orig);
    }

    // Store vectors into state.
    vst1q_u32(state[0..4].as_mut_ptr(), abcd);
    vst1q_u32(state[4..8].as_mut_ptr(), efgh);
}
