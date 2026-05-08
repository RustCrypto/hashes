use keccak::State1600;
use sponge_cursor::SpongeCursor;

#[inline(always)]
pub(crate) fn pad<const PAD: u8, const RATE: usize>(
    state: &mut State1600,
    cursor: &SpongeCursor<RATE>,
) {
    let pos = cursor.pos();
    let word_offset = pos / 8;
    let byte_offset = pos % 8;

    let pad = u64::from(PAD) << (8 * byte_offset);
    state[word_offset] ^= pad;
    state[RATE / 8 - 1] ^= 1 << 63;
}

#[inline(always)]
pub(crate) fn read_state(state: &State1600, dst: &mut [u8]) {
    assert!(size_of_val(dst) <= size_of_val(state));

    let chunks = dst.chunks_mut(size_of::<u64>());
    for (src, dst) in state.iter().zip(chunks) {
        dst.copy_from_slice(&src.to_le_bytes()[..dst.len()]);
    }
}

#[inline(always)]
pub(crate) fn serialize<const RATE: usize>(
    state: &State1600,
    cursor: &SpongeCursor<RATE>,
) -> [u8; 201] {
    let mut ser_state = [0u8; 201];
    // TODO(MSRV-1.88): use `ser_state.as_chunks_mut()`
    let [state_dst @ .., cursor_dst] = &mut ser_state;

    let state_dst_chunks = state_dst.chunks_exact_mut(size_of::<u64>());
    for (src, dst) in state.iter().zip(state_dst_chunks) {
        dst.copy_from_slice(&src.to_le_bytes());
    }

    *cursor_dst = cursor.raw_pos();
    ser_state
}

#[inline(always)]
pub(crate) fn deserialize<const RATE: usize>(
    ser_state: &[u8; 201],
) -> Option<(State1600, SpongeCursor<RATE>)> {
    // TODO(MSRV-1.88): use `ser_state.as_chunks()`
    let [state_src @ .., cursor_src] = ser_state;

    let n = size_of::<u64>();
    let state = core::array::from_fn(|i| {
        let chunk = state_src[n * i..][..n]
            .try_into()
            .expect("chunk has correct length");
        u64::from_le_bytes(chunk)
    });

    let cursor = SpongeCursor::new(*cursor_src)?;
    Some((state, cursor))
}
