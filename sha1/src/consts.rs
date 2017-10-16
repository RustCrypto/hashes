pub const STATE_LEN: usize = 5;

#[cfg(not(feature = "asm"))]
pub const BLOCK_LEN: usize = 16;

#[cfg(not(feature = "asm"))]
pub const K0: u32 = 0x5A82_7999u32;
#[cfg(not(feature = "asm"))]
pub const K1: u32 = 0x6ED9_EBA1u32;
#[cfg(not(feature = "asm"))]
pub const K2: u32 = 0x8F1B_BCDCu32;
#[cfg(not(feature = "asm"))]
pub const K3: u32 = 0xCA62_C1D6u32;

pub const H: [u32; STATE_LEN] = [
    0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0
];
