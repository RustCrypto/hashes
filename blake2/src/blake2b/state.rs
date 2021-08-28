use super::{backend, Count, Hash, Params, Word, BLOCKBYTES, OUTBYTES};
use arrayref::mut_array_refs;
use core::{cmp, fmt, mem::size_of};

/// An incremental hasher for BLAKE2b.
///
/// To construct a `State` with non-default parameters, see `Params::to_state`.
///
/// # Example
///
/// ```
/// use blake2::blake2b::{blake2b, State};
///
/// let mut state = State::new();
///
/// state.update(b"foo");
/// assert_eq!(blake2b(b"foo"), state.finalize());
///
/// state.update(b"bar");
/// assert_eq!(blake2b(b"foobar"), state.finalize());
/// ```
#[derive(Clone)]
pub struct State {
    pub(super) words: [Word; 8],
    pub(super) count: Count,
    pub(super) buf: [u8; BLOCKBYTES],
    pub(super) buflen: u8,
    pub(super) last_node: backend::LastNode,
    hash_length: u8,
    pub(super) implementation: backend::Implementation,
    is_keyed: bool,
}

impl State {
    /// Equivalent to `State::default()` or `Params::default().to_state()`.
    pub fn new() -> Self {
        Self::with_params(&Params::default())
    }

    pub(super) fn with_params(params: &Params) -> Self {
        let mut state = Self {
            words: params.to_words(),
            count: 0,
            buf: [0; BLOCKBYTES],
            buflen: 0,
            last_node: params.last_node,
            hash_length: params.hash_length,
            implementation: params.implementation,
            is_keyed: params.key_length > 0,
        };
        if state.is_keyed {
            state.buf = params.key_block;
            state.buflen = state.buf.len() as u8;
        }
        state
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let take = cmp::min(BLOCKBYTES - self.buflen as usize, input.len());
        self.buf[self.buflen as usize..self.buflen as usize + take].copy_from_slice(&input[..take]);
        self.buflen += take as u8;
        *input = &input[take..];
    }

    // If the state already has some input in its buffer, try to fill the buffer and perform a
    // compression. However, only do the compression if there's more input coming, otherwise it
    // will give the wrong hash it the caller finalizes immediately after.
    pub(super) fn compress_buffer_if_possible(&mut self, input: &mut &[u8]) {
        if self.buflen > 0 {
            self.fill_buf(input);
            if !input.is_empty() {
                self.implementation.compress1_loop(
                    &self.buf,
                    &mut self.words,
                    self.count,
                    self.last_node,
                    backend::Finalize::No,
                    backend::Stride::Serial,
                );
                self.count = self.count.wrapping_add(BLOCKBYTES as Count);
                self.buflen = 0;
            }
        }
    }

    /// Add input to the hash. You can call `update` any number of times.
    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        // If we have a partial buffer, try to complete it.
        self.compress_buffer_if_possible(&mut input);
        // While there's more than a block of input left (which also means we cleared the buffer
        // above), compress blocks directly without copying.
        let mut end = input.len().saturating_sub(1);
        end -= end % BLOCKBYTES;
        if end > 0 {
            self.implementation.compress1_loop(
                &input[..end],
                &mut self.words,
                self.count,
                self.last_node,
                backend::Finalize::No,
                backend::Stride::Serial,
            );
            self.count = self.count.wrapping_add(end as Count);
            input = &input[end..];
        }
        // Buffer any remaining input, to be either compressed or finalized in a subsequent call.
        // Note that this represents some copying overhead, which in theory we could avoid in
        // all-at-once setting. A function hardcoded for exactly BLOCKSIZE input bytes is about 10%
        // faster than using this implementation for the same input.
        self.fill_buf(&mut input);
        self
    }

    /// Finalize the state and return a `Hash`. This method is idempotent, and calling it multiple
    /// times will give the same result. It's also possible to `update` with more input in between.
    pub fn finalize(&self) -> Hash {
        let mut words_copy = self.words;
        self.implementation.compress1_loop(
            &self.buf[..self.buflen as usize],
            &mut words_copy,
            self.count,
            self.last_node,
            backend::Finalize::Yes,
            backend::Stride::Serial,
        );
        Hash {
            bytes: words_to_bytes(&words_copy),
            len: self.hash_length,
        }
    }

    /// Set a flag indicating that this is the last node of its level in a tree hash. This is
    /// equivalent to [`Params::last_node`], except that it can be set at any time before calling
    /// `finalize`. That allows callers to begin hashing a node without knowing ahead of time
    /// whether it's the last in its level. For more details about the intended use of this flag
    /// [the BLAKE2 spec].
    ///
    /// [`Params::last_node`]: struct.Params.html#method.last_node
    /// [the BLAKE2 spec]: https://blake2.net/blake2.pdf
    pub fn set_last_node(&mut self, last_node: bool) -> &mut Self {
        self.last_node = if last_node {
            backend::LastNode::Yes
        } else {
            backend::LastNode::No
        };
        self
    }

    /// Return the total number of bytes input so far.
    ///
    /// Note that `count` doesn't include the bytes of the key block, if any.
    /// It's exactly the total number of input bytes fed to `update`.
    pub fn count(&self) -> Count {
        let mut ret = self.count.wrapping_add(self.buflen as Count);
        if self.is_keyed {
            ret -= BLOCKBYTES as Count;
        }
        ret
    }
}

#[cfg(feature = "std")]
impl std::io::Write for State {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NB: Don't print the words. Leaking them would allow length extension.
        write!(
            f,
            "State {{ count: {}, hash_length: {}, last_node: {} }}",
            self.count(),
            self.hash_length,
            self.last_node.yes(),
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::with_params(&Params::default())
    }
}

#[inline(always)]
pub(crate) fn words_to_bytes(state_words: &[Word; 8]) -> [u8; OUTBYTES] {
    let mut bytes = [0; OUTBYTES];
    {
        const W: usize = size_of::<Word>();
        let refs = mut_array_refs!(&mut bytes, W, W, W, W, W, W, W, W);
        *refs.0 = state_words[0].to_le_bytes();
        *refs.1 = state_words[1].to_le_bytes();
        *refs.2 = state_words[2].to_le_bytes();
        *refs.3 = state_words[3].to_le_bytes();
        *refs.4 = state_words[4].to_le_bytes();
        *refs.5 = state_words[5].to_le_bytes();
        *refs.6 = state_words[6].to_le_bytes();
        *refs.7 = state_words[7].to_le_bytes();
    }
    bytes
}
