#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Portable,
    #[cfg(feature = "asm")]
    Asm,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Sha,
}

#[derive(Clone, Copy, Debug)]
pub struct Implementation(Platform);

impl Implementation {
    pub fn detect() -> Self {
        // Try the different implementations in order of how fast/modern they are.
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if let Some(sha_impl) = Self::sha_if_supported() {
                return sha_impl;
            }
        }
        #[cfg(feature = "asm")]
        {
            if let Some(asm_impl) = Self::asm_if_supported() {
                return asm_impl;
            }
        }

        Self::portable()
    }

    pub fn portable() -> Self {
        Implementation(Platform::Portable)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[allow(unreachable_code)]
    pub fn sha_if_supported() -> Option<Self> {
        // Check whether sha support is assumed by the build.
        #[cfg(target_feature = "sha")]
        {
            return Some(Implementation(Platform::Sha));
        }
        // Otherwise dynamically check for support if we can.
        #[cfg(feature = "std")]
        {
            if std::is_x86_feature_detected!("sha") {
                return Some(Implementation(Platform::Sha));
            }
        }
        None
    }

    #[cfg(feature = "asm")]
    pub fn asm_if_supported() -> Option<Self> {
        return Some(Implementation(Platform::Asm));
    }

    #[inline]
    pub fn compress256(&self, state: &mut [u32; 8], block: &[u8; 64]) {
        match self.0 {
            Platform::Portable => {
                use crate::sha256_utils;
                sha256_utils::compress256(state, block);
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Platform::Sha => {
                use crate::sha256_intrinsics;
                unsafe { sha256_intrinsics::compress256(state, block) };
            }
            #[cfg(feature = "asm")]
            Platform::Asm => {
                sha2_asm::compress256(state, block);
            }
        }
    }
}
