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
        #[cfg(any(feature = "asm", feature = "asm-aarch64"))]
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
        use raw_cpuid::CpuId;

        // Use raw_cpuid instead of is_x86_feature_detected, to ensure the check
        // never happens at compile time.
        let cpuid = CpuId::new();
        let is_runtime_ok = cpuid
            .get_extended_feature_info()
            .map(|info| info.has_sha())
            .unwrap_or_default();

        // Make sure this computer actually supports it
        if is_runtime_ok {
            return Some(Implementation(Platform::Sha));
        }

        None
    }

    #[cfg(any(feature = "asm", feature = "asm-arch64"))]
    pub fn asm_if_supported() -> Option<Self> {
        #[cfg(feature = "asm-aarch64")]
        let supported = ::aarch64::sha2_supported();
        #[cfg(not(feature = "asm-aarch64"))]
        let supported = false;

        if supported {
            return Some(Implementation(Platform::Asm));
        }
        None
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
