//! HAS-160 constants.

/// Internal state length (5 x 32-bit words = 160 bits)
pub(crate) const STATE_LEN: usize = 5;

pub(crate) const STATE_INIT: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_init_values_match_expected() {
        assert_eq!(STATE_INIT[0], 0x6745_2301);
        assert_eq!(STATE_INIT[4], 0xC3D2_E1F0);
    }


}
