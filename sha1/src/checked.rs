//! Checked Sha1.

#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, ZeroizeOnDrop};
use digest::{
    block_buffer::BlockBuffer,
    core_api::{BlockSizeUser, BufferKindUser, FixedOutputCore, UpdateCore},
    crypto_common::InnerUser,
    FixedOutput, FixedOutputReset, HashMarker, InnerInit, MacMarker, Output, OutputSizeUser, Reset,
    Update,
};

use crate::Sha1Core;

pub(crate) mod ubc_check;

/// SHA-1 collision detection hasher state.
#[derive(Clone)]
pub struct Sha1 {
    core: Sha1Core,
    buffer: BlockBuffer<
        <Sha1Core as BlockSizeUser>::BlockSize,
        <Sha1Core as BufferKindUser>::BufferKind,
    >,
}

impl HashMarker for Sha1 {}

impl MacMarker for Sha1 {}

// this blanket impl is needed for HMAC
impl BlockSizeUser for Sha1 {
    type BlockSize = <Sha1Core as BlockSizeUser>::BlockSize;
}

impl Default for Sha1 {
    fn default() -> Self {
        Builder::default().build()
    }
}

impl Sha1 {
    /// Create a new Sha1 instance, with collision detection enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new Sha1 builder to configure detection.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Create a new Sha1 instance from a `core`.
    #[inline]
    pub fn from_core(core: Sha1Core) -> Self {
        let buffer = Default::default();
        Self { core, buffer }
    }

    /// Try finalization, reporting the collision state.
    pub fn try_finalize(mut self) -> CollisionResult {
        let mut out = Output::<Sha1Core>::default();
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, &mut out);

        if let Some(ref ctx) = core.detection {
            if ctx.found_collision {
                if ctx.safe_hash {
                    return CollisionResult::Mitigated(out);
                }
                return CollisionResult::Collision(out);
            }
        }
        CollisionResult::Ok(out)
    }
}

/// Result when trying to finalize a hash.
#[derive(Debug)]
pub enum CollisionResult {
    /// No collision.
    Ok(Output<Sha1Core>),
    /// Collision occured, but was mititgated.
    Mitigated(Output<Sha1Core>),
    /// Collision occured, the hash is the one that collided.
    Collision(Output<Sha1Core>),
}

impl CollisionResult {
    /// Returns the output hash.
    pub fn hash(&self) -> &Output<Sha1Core> {
        match self {
            CollisionResult::Ok(ref s) => s,
            CollisionResult::Mitigated(ref s) => s,
            CollisionResult::Collision(ref s) => s,
        }
    }

    /// Returns if there was a collision
    pub fn has_collision(&self) -> bool {
        !matches!(self, CollisionResult::Ok(_))
    }
}

impl InnerUser for Sha1 {
    type Inner = Sha1Core;
}

impl InnerInit for Sha1 {
    fn inner_init(inner: Self::Inner) -> Self {
        Self::from_core(inner)
    }
}

impl core::fmt::Debug for Sha1 {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.write_str("Sha1CollisionDetection { .. }")
    }
}

impl Reset for Sha1 {
    #[inline]
    fn reset(&mut self) {
        self.core.reset();
        self.buffer.reset();
    }
}

impl Update for Sha1 {
    #[inline]
    fn update(&mut self, input: &[u8]) {
        let Self { core, buffer } = self;
        buffer.digest_blocks(input, |blocks| core.update_blocks(blocks));
    }
}

impl OutputSizeUser for Sha1 {
    type OutputSize = <Sha1Core as OutputSizeUser>::OutputSize;
}

impl FixedOutput for Sha1 {
    #[inline]
    fn finalize_into(mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = &mut self;
        core.finalize_fixed_core(buffer, out);
    }
}

impl FixedOutputReset for Sha1 {
    #[inline]
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let Self { core, buffer } = self;
        core.finalize_fixed_core(buffer, out);
        core.reset();
        buffer.reset();
    }
}

impl Drop for Sha1 {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.buffer.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for Sha1 {}

impl Drop for DetectionState {
    #[inline]
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.ihv1.zeroize();
            self.ihv2.zeroize();
            self.m1.zeroize();
            self.m2.zeroize();
            self.state_58.zeroize();
            self.state_65.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for DetectionState {}

#[cfg(feature = "oid")]
impl digest::const_oid::AssociatedOid for Sha1 {
    const OID: digest::const_oid::ObjectIdentifier = Sha1Core::OID;
}

#[cfg(feature = "std")]
impl std::io::Write for Sha1 {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Update::update(self, buf);
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Builder for collision detection configuration.
#[derive(Clone)]
pub struct Builder {
    detect_collision: bool,
    safe_hash: bool,
    ubc_check: bool,
    reduced_round_collision: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            detect_collision: true,
            safe_hash: true,
            ubc_check: true,
            reduced_round_collision: false,
        }
    }
}

impl Builder {
    /// Should we detect collisions at all? Default: true
    pub fn detect_collision(mut self, detect: bool) -> Self {
        self.detect_collision = detect;
        self
    }

    /// Should a fix be automatically be applied, or the original hash be returned? Default: true
    pub fn safe_hash(mut self, safe_hash: bool) -> Self {
        self.safe_hash = safe_hash;
        self
    }

    /// Should unavoidable bitconditions be used to speed up the check? Default: true
    pub fn use_ubc(mut self, ubc: bool) -> Self {
        self.ubc_check = ubc;
        self
    }

    /// Should reduced round collisions be used? Default: false
    pub fn reduced_round_collision(mut self, reduced: bool) -> Self {
        self.reduced_round_collision = reduced;
        self
    }

    fn into_detection_state(self) -> Option<DetectionState> {
        if self.detect_collision {
            Some(DetectionState {
                safe_hash: self.safe_hash,
                reduced_round_collision: self.reduced_round_collision,
                ubc_check: self.ubc_check,
                found_collision: false,
                ihv1: Default::default(),
                ihv2: Default::default(),
                m1: [0; 80],
                m2: [0; 80],
                state_58: Default::default(),
                state_65: Default::default(),
            })
        } else {
            None
        }
    }

    /// Create a Sha1 with a specific collision detection configuration.
    pub fn build(self) -> Sha1 {
        let detection = self.into_detection_state();
        let core = Sha1Core {
            detection,
            ..Default::default()
        };
        Sha1::from_core(core)
    }
}

/// The internal state used to do collision detection.
#[derive(Clone, Debug)]
pub struct DetectionState {
    pub(crate) safe_hash: bool,
    pub(crate) ubc_check: bool,
    pub(crate) reduced_round_collision: bool,
    /// Has a collision been detected?
    pub(crate) found_collision: bool,
    pub(crate) ihv1: [u32; 5],
    pub(crate) ihv2: [u32; 5],
    pub(crate) m1: [u32; 80],
    pub(crate) m2: [u32; 80],
    /// Stores past states, for faster recompression.
    pub(crate) state_58: [u32; 5],
    pub(crate) state_65: [u32; 5],
}

impl Default for DetectionState {
    fn default() -> Self {
        Builder::default()
            .into_detection_state()
            .expect("enabled by default")
    }
}

impl DetectionState {
    pub(crate) fn reset(&mut self) {
        // Do not reset the config, it needs to be preserved

        self.found_collision = false;
        self.ihv1 = Default::default();
        self.ihv2 = Default::default();
        self.m1 = [0; 80];
        self.m2 = [0; 80];
        self.state_58 = Default::default();
        self.state_65 = Default::default();
    }
}
