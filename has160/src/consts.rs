//! HAS-160 constants.

/// Internal state length (5 x 32-bit words = 160 bits)
const STATE_LEN: usize = 5;

pub(crate) const STATE_INIT: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

pub(crate) const K: [u32; 4] = [
    0x5A82_7999,
    0x6ED9_EBA1,
    0x8F1B_BCDC,
    0xCA62_C1D6,
];

pub(crate) enum RoundClass {
    /// First 20 rounds (0..19)
    Group0,
    /// Rounds 20..39
    Group1,
    /// Rounds 40..59
    Group2,
    /// Rounds 60..79
    Group3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_init_values_match_expected() {
        assert_eq!(STATE_INIT[0], 0x6745_2301);
        assert_eq!(STATE_INIT[4], 0xC3D2_E1F0);
    }

    #[test]
    fn k_constants_match_expected() {
        assert_eq!(K, [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6]);
    }
}
