use super::{
    backend, state, Hash, State, Word, BLOCKBYTES, IV, KEYBYTES, OUTBYTES, PERSONALBYTES, SALTBYTES,
};
use arrayref::array_refs;
use core::fmt;

/// A parameter builder that exposes all the non-default BLAKE2 features.
///
/// Apart from `hash_length`, which controls the length of the final `Hash`,
/// all of these parameters are just associated data that gets mixed with the
/// input. For more details, see [the BLAKE2 spec](https://blake2.net/blake2.pdf).
///
/// Several of the parameters have a valid range defined in the spec and
/// documented below. Trying to set an invalid parameter will panic.
///
/// # Example
///
/// ```
/// # use blake2::blake2b::Params;
/// // Create a Params object with a secret key and a non-default length.
/// let mut params = Params::new();
/// params.key(b"my secret key");
/// params.hash_length(16);
///
/// // Use those params to hash an input all at once.
/// let hash = params.hash(b"my input");
///
/// // Or use those params to build an incremental State.
/// let mut state = params.to_state();
/// ```
#[derive(Clone)]
pub struct Params {
    pub(super) hash_length: u8,
    pub(super) key_length: u8,
    pub(super) key_block: [u8; BLOCKBYTES],
    salt: [u8; SALTBYTES],
    personal: [u8; PERSONALBYTES],
    fanout: u8,
    max_depth: u8,
    max_leaf_length: u32,
    node_offset: u64,
    node_depth: u8,
    inner_hash_length: u8,
    pub(super) last_node: backend::LastNode,
    pub(super) implementation: backend::Implementation,
}

impl Params {
    /// Equivalent to `Params::default()`.
    #[inline]
    pub fn new() -> Self {
        Self {
            hash_length: OUTBYTES as u8,
            key_length: 0,
            key_block: [0; BLOCKBYTES],
            salt: [0; SALTBYTES],
            personal: [0; PERSONALBYTES],
            // NOTE: fanout and max_depth don't default to zero!
            fanout: 1,
            max_depth: 1,
            max_leaf_length: 0,
            node_offset: 0,
            node_depth: 0,
            inner_hash_length: 0,
            last_node: backend::LastNode::No,
            implementation: backend::Implementation::detect(),
        }
    }

    #[inline(always)]
    pub(crate) fn to_words(&self) -> [Word; 8] {
        let (salt_left, salt_right) = array_refs!(&self.salt, SALTBYTES / 2, SALTBYTES / 2);
        let (personal_left, personal_right) =
            array_refs!(&self.personal, PERSONALBYTES / 2, PERSONALBYTES / 2);
        [
            IV[0]
                ^ self.hash_length as u64
                ^ (self.key_length as u64) << 8
                ^ (self.fanout as u64) << 16
                ^ (self.max_depth as u64) << 24
                ^ (self.max_leaf_length as u64) << 32,
            IV[1] ^ self.node_offset,
            IV[2] ^ self.node_depth as u64 ^ (self.inner_hash_length as u64) << 8,
            IV[3],
            IV[4] ^ Word::from_le_bytes(*salt_left),
            IV[5] ^ Word::from_le_bytes(*salt_right),
            IV[6] ^ Word::from_le_bytes(*personal_left),
            IV[7] ^ Word::from_le_bytes(*personal_right),
        ]
    }

    /// Hash an input all at once with these parameters.
    #[inline]
    pub fn hash(&self, input: &[u8]) -> Hash {
        // If there's a key, just fall back to using the State.
        if self.key_length > 0 {
            return self.to_state().update(input).finalize();
        }
        let mut words = self.to_words();
        self.implementation.compress1_loop(
            input,
            &mut words,
            0,
            self.last_node,
            backend::Finalize::Yes,
            backend::Stride::Serial,
        );
        Hash {
            bytes: state::words_to_bytes(&words),
            len: self.hash_length,
        }
    }

    /// Construct a `State` object based on these parameters, for hashing input
    /// incrementally.
    pub fn to_state(&self) -> State {
        State::with_params(self)
    }

    /// Set the length of the final hash in bytes, from 1 to `OUTBYTES` (64). Apart from
    /// controlling the length of the final `Hash`, this is also associated data, and changing it
    /// will result in a totally different hash.
    #[inline]
    pub fn hash_length(&mut self, length: usize) -> &mut Self {
        assert!(
            (1..=OUTBYTES).contains(&length),
            "Bad hash length: {}",
            length
        );
        self.hash_length = length as u8;
        self
    }

    /// Use a secret key, so that BLAKE2 acts as a MAC. The maximum key length is `KEYBYTES` (64).
    /// An empty key is equivalent to having no key at all.
    #[inline]
    pub fn key(&mut self, key: &[u8]) -> &mut Self {
        assert!(key.len() <= KEYBYTES, "Bad key length: {}", key.len());
        self.key_length = key.len() as u8;
        self.key_block = [0; BLOCKBYTES];
        self.key_block[..key.len()].copy_from_slice(key);
        self
    }

    /// At most `SALTBYTES` (16). Shorter salts are padded with null bytes. An empty salt is
    /// equivalent to having no salt at all.
    #[inline]
    pub fn salt(&mut self, salt: &[u8]) -> &mut Self {
        assert!(salt.len() <= SALTBYTES, "Bad salt length: {}", salt.len());
        self.salt = [0; SALTBYTES];
        self.salt[..salt.len()].copy_from_slice(salt);
        self
    }

    /// At most `PERSONALBYTES` (16). Shorter personalizations are padded with null bytes. An empty
    /// personalization is equivalent to having no personalization at all.
    #[inline]
    pub fn personal(&mut self, personalization: &[u8]) -> &mut Self {
        assert!(
            personalization.len() <= PERSONALBYTES,
            "Bad personalization length: {}",
            personalization.len()
        );
        self.personal = [0; PERSONALBYTES];
        self.personal[..personalization.len()].copy_from_slice(personalization);
        self
    }

    /// From 0 (meaning unlimited) to 255. The default is 1 (meaning sequential).
    #[inline]
    pub fn fanout(&mut self, fanout: u8) -> &mut Self {
        self.fanout = fanout;
        self
    }

    /// From 0 (meaning BLAKE2X B2 hashes), through 1 (the default, meaning sequential) to 255 (meaning unlimited).
    #[inline]
    pub fn max_depth(&mut self, depth: u8) -> &mut Self {
        self.max_depth = depth;
        self
    }

    /// From 0 (the default, meaning unlimited or sequential) to `2^32 - 1`.
    #[inline]
    pub fn max_leaf_length(&mut self, length: u32) -> &mut Self {
        self.max_leaf_length = length;
        self
    }

    /// From 0 (the default, meaning first, leftmost, leaf, or sequential) to `2^64 - 1`.
    #[inline]
    pub fn node_offset(&mut self, offset: u64) -> &mut Self {
        self.node_offset = offset;
        self
    }

    /// From 0 (the default, meaning leaf or sequential) to 255.
    #[inline]
    pub fn node_depth(&mut self, depth: u8) -> &mut Self {
        self.node_depth = depth;
        self
    }

    /// From 0 (the default, meaning sequential) to `OUTBYTES` (64).
    #[inline]
    pub fn inner_hash_length(&mut self, length: usize) -> &mut Self {
        assert!(length <= OUTBYTES, "Bad inner hash length: {}", length);
        self.inner_hash_length = length as u8;
        self
    }

    /// Indicates the rightmost node in a row. This can also be changed on the
    /// `State` object, potentially after hashing has begun. See
    /// [`State::set_last_node`].
    ///
    /// [`State::set_last_node`]: struct.State.html#method.set_last_node
    #[inline]
    pub fn last_node(&mut self, last_node: bool) -> &mut Self {
        self.last_node = if last_node {
            backend::LastNode::Yes
        } else {
            backend::LastNode::No
        };
        self
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Params {{ hash_length: {}, key_length: {}, salt: {:?}, personal: {:?}, fanout: {}, \
             max_depth: {}, max_leaf_length: {}, node_offset: {}, node_depth: {}, \
             inner_hash_length: {}, last_node: {} }}",
            self.hash_length,
            // NB: Don't print the key itself. Debug shouldn't leak secrets.
            self.key_length,
            &self.salt,
            &self.personal,
            self.fanout,
            self.max_depth,
            self.max_leaf_length,
            self.node_offset,
            self.node_depth,
            self.inner_hash_length,
            self.last_node.yes(),
        )
    }
}
