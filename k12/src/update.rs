use crate::{
    Kt,
    consts::{CHUNK_SIZE, CHUNK_SIZE_U64, ROUNDS, S0_DELIM},
    node_turbo_shake,
};
use digest::{block_buffer::BlockSizes, typenum::Unsigned};
use keccak::{Backend, BackendClosure};

/// Buffer size used by the update closure.
///
/// 512 byte buffer is sufficient for 16x and 8x parallel KT128 and KT256 respectively.
const BUFFER_LEN: usize = 512;

pub(crate) struct Closure<'a, Rate: BlockSizes> {
    pub(crate) data: &'a [u8],
    pub(crate) kt: &'a mut Kt<Rate>,
}

impl<Rate: BlockSizes> BackendClosure for Closure<'_, Rate> {
    #[inline(always)]
    fn call_once<B: Backend>(self) {
        let Kt {
            accum_tshk,
            node_tshk,
            consumed_len,
            ..
        } = self.kt;
        let mut data = self.data;

        let par_p1600 = B::get_par_p1600::<ROUNDS>();
        let p1600 = B::get_p1600::<ROUNDS>();
        let par_size = B::ParSize1600::USIZE;
        let cv_len = 200 - Rate::USIZE;
        // TODO: this should be [0u8; par_size * cv_len]`
        let mut cv_buf = [0u8; BUFFER_LEN];

        // Handle the S_0 chunk which is absorbed directly by the CV accumulator
        if let Some(s0_rem_len) = CHUNK_SIZE_U64.checked_sub(*consumed_len) {
            let s0_rem_len = usize::try_from(s0_rem_len)
                .expect("the value is smaller or equal to CHUNK_SIZE_U64");

            let (part_data, rem_data) = data.split_at_checked(s0_rem_len).unwrap_or((data, &[]));

            accum_tshk.absorb(p1600, part_data);
            *consumed_len += u64::try_from(part_data.len()).expect("length fits into `u64`");
            if rem_data.is_empty() {
                return;
            }
            debug_assert_eq!(*consumed_len, CHUNK_SIZE_U64);
            // Note that `consumed_len` does not account for `S0_DELIM`
            accum_tshk.absorb(p1600, &S0_DELIM.to_le_bytes());
            data = rem_data;
        }

        let partial_chunk_len = usize::try_from(*consumed_len % CHUNK_SIZE_U64)
            .expect("the remainder is always smaller than CHUNK_SIZE");
        *consumed_len += u64::try_from(data.len()).expect("`data.len()` fits into `u64`");

        // Handle partially absorbed chunk
        if partial_chunk_len != 0 {
            let rem_len = CHUNK_SIZE - partial_chunk_len;
            let split = data.split_at_checked(rem_len);

            let Some((part_data, rem_data)) = split else {
                node_tshk.absorb(p1600, data);
                return;
            };

            node_tshk.absorb(p1600, part_data);

            let cv_dst = &mut cv_buf[..cv_len];
            node_tshk.full_node_finalize(p1600, cv_dst);
            accum_tshk.absorb(p1600, cv_dst);

            *node_tshk = Default::default();
            data = rem_data;
        }

        if data.is_empty() {
            return;
        }

        // Handle full 8 KiB chunks using the parallel function if the selected backend supports it
        if par_size > 1 {
            let cvs_dst = &mut cv_buf[..par_size * cv_len];
            let mut par_data_chunks = data.chunks_exact(par_size * CHUNK_SIZE);

            for par_data_chunk in &mut par_data_chunks {
                node_turbo_shake::parallel::<_, Rate>(par_p1600, par_data_chunk, cvs_dst);
                accum_tshk.absorb(p1600, cvs_dst);
            }
            data = par_data_chunks.remainder();
        }

        // Handle full 8 KiB chunks using the scalar function
        let cv_dst = &mut cv_buf[..cv_len];
        let mut data_chunks = data.chunks_exact(CHUNK_SIZE);
        for data_chunk in &mut data_chunks {
            node_turbo_shake::scalar::<Rate>(p1600, data_chunk, cv_dst);
            accum_tshk.absorb(p1600, cv_dst);
        }
        data = data_chunks.remainder();

        // Absorb the remaining data
        node_tshk.absorb(p1600, data);
    }
}
