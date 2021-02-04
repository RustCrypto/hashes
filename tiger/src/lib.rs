//! The [Tiger][1] hash function, implemented through [Digest][2]
//!
//! [1]: http://www.cs.technion.ac.il/~biham/Reports/Tiger/tiger/tiger.html
//! [2]: https://crates.io/crates/digest

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest;

use block_buffer::{
    generic_array::typenum::consts::U64 as BB_U64, generic_array::GenericArray as BB_GenericArray,
    BlockBuffer,
};
use byteorder::{ByteOrder, LE};
use digest::generic_array::typenum::{U24, U64};
use digest::generic_array::GenericArray;

type BlockBuffer512 = BlockBuffer<BB_U64>;

const PADDING_BLOCK: [u8; 64] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

const H0: [u64; 3] = [
    0x0123_4567_89AB_CDEF,
    0xFEDC_BA98_7654_3210,
    0xF096_A5B4_C3B2_E187,
];

/// The Tiger hasher
#[derive(Clone)]
pub struct Tiger {
    length_bytes: u64,
    buffer: BlockBuffer512,
    state: [u64; 3],
}

impl Default for Tiger {
    fn default() -> Self {
        Tiger {
            length_bytes: 0,
            buffer: Default::default(),
            state: H0,
        }
    }
}

impl Tiger {
    #[inline]
    fn fill_up_to(from: usize, to: usize, modulo: usize) -> usize {
        let _from = from + 1;
        let _to = to + modulo;
        1 + ((_to - _from) % modulo)
    }

    #[inline]
    fn finalize(&mut self) -> [u64; 3] {
        {
            let self_state = &mut self.state;
            let pad_size = Self::fill_up_to(self.buffer.position(), 64 - 8, 64);
            self.buffer.input_block(&PADDING_BLOCK[..pad_size], |d| {
                Self::compress(self_state, d)
            });

            let mut length: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
            LE::write_u64(&mut length, (self.length_bytes << 3) as u64);
            self.buffer
                .input_block(&length, |d| Self::compress(self_state, d));

            assert_eq!(self.buffer.position(), 0);
        }
        self.state
    }

    fn consume(&mut self, input: &[u8]) {
        // Unlike Sha1 and Sha2, the length value in Tiger is defined as
        // the length of the message mod 2^64 - ie: integer overflow is OK.
        self.length_bytes += input.len() as u64;
        let self_state = &mut self.state;
        self.buffer
            .input_block(input, |d| Self::compress(self_state, d));
    }

    #[inline]
    fn compress(state: &mut [u64; 3], input: &BB_GenericArray<u8, BB_U64>) {
        let mut inputs: [u64; 8] = Default::default();
        LE::read_u64_into(input, &mut inputs);
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];

        Self::pass(&mut a, &mut b, &mut c, &inputs, 5);
        Self::key_schedule(&mut inputs);
        Self::pass(&mut c, &mut a, &mut b, &inputs, 7);
        Self::key_schedule(&mut inputs);
        Self::pass(&mut b, &mut c, &mut a, &inputs, 9);

        state[0] ^= a;
        state[1] = b.wrapping_sub(state[1]);
        state[2] = c.wrapping_add(state[2]);
    }

    #[inline]
    fn pass(a: &mut u64, b: &mut u64, c: &mut u64, x: &[u64; 8], mul: u8) {
        Self::round(a, b, c, &x[0], mul);
        Self::round(b, c, a, &x[1], mul);
        Self::round(c, a, b, &x[2], mul);
        Self::round(a, b, c, &x[3], mul);
        Self::round(b, c, a, &x[4], mul);
        Self::round(c, a, b, &x[5], mul);
        Self::round(a, b, c, &x[6], mul);
        Self::round(b, c, a, &x[7], mul);
    }

    #[inline]
    fn round(a: &mut u64, b: &mut u64, c: &mut u64, x: &u64, mul: u8) {
        *c ^= *x;
        let mut c_: [u8; 8] = Default::default();
        LE::write_u64(&mut c_, *c);
        *a = a.wrapping_sub(
            T1[c_[0] as usize] ^ T2[c_[2] as usize] ^ T3[c_[4] as usize] ^ T4[c_[6] as usize],
        );
        *b = b.wrapping_add(
            T4[c_[1] as usize] ^ T3[c_[3] as usize] ^ T2[c_[5] as usize] ^ T1[c_[7] as usize],
        );
        *b = b.wrapping_mul(u64::from(mul));
    }

    #[inline]
    fn key_schedule(x: &mut [u64; 8]) {
        x[0] = x[0].wrapping_sub(x[7] ^ 0xA5A5_A5A5_A5A5_A5A5);
        x[1] ^= x[0];
        x[2] = x[2].wrapping_add(x[1]);
        x[3] = x[3].wrapping_sub(x[2] ^ ((!x[1]) << 19));
        x[4] ^= x[3];
        x[5] = x[5].wrapping_add(x[4]);
        x[6] = x[6].wrapping_sub(x[5] ^ ((!x[4]) >> 23));
        x[7] ^= x[6];
        x[0] = x[0].wrapping_add(x[7]);
        x[1] = x[1].wrapping_sub(x[0] ^ ((!x[7]) << 19));
        x[2] ^= x[1];
        x[3] = x[3].wrapping_add(x[2]);
        x[4] = x[4].wrapping_sub(x[3] ^ ((!x[2]) >> 23));
        x[5] ^= x[4];
        x[6] = x[6].wrapping_add(x[5]);
        x[7] = x[7].wrapping_sub(x[6] ^ 0x0123_4567_89AB_CDEF);
    }
}

impl digest::BlockInput for Tiger {
    type BlockSize = U64;
}

impl digest::Reset for Tiger {
    fn reset(&mut self) {
        self.buffer.reset();
        self.length_bytes = 0;
        self.state = H0;
    }
}

impl digest::Update for Tiger {
    #[inline]

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.consume(data.as_ref());
    }
}

impl digest::FixedOutputDirty for Tiger {
    type OutputSize = U24;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        LE::write_u64_into(&self.finalize(), &mut out.as_mut_slice());
    }
}

// Conditionally compile the module `test` only when the test-suite is run.
#[cfg(test)]
mod test {
    use super::Tiger;
    use digest::Digest;
    use hex_literal::hex;

    #[test]
    fn test_vectors() {
        let examples = [
            ("", hex!("3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3")),
            ("abc", hex!("2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93")),
            ("Tiger", hex!("dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937")),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
                hex!("f71c8583902afb879edfe610f82c0d4786a3a534504486b5"),
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
                hex!("48ceeb6308b87d46e95d656112cdf18d97915f9765658957"),
            ),
            (
                "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
                hex!("8a866829040a410c729ad23f5ada711603b3cdd357e4c15e"),
            ),
            (
                "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.",
                hex!("ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889"),
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                hex!("0f7bf9a19b9c58f2b7610df7e84f0ac3a71c631e7b53f78e"),
            ),
            (
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                hex!("08c8dcb467e4c7f910966c399fdc9b164be15b792d432224"),
            ),
        ];

        for &(input, answer) in examples.iter() {
            let result = Tiger::digest(input.as_bytes());

            assert_eq!(*result, answer);
        }
    }
}

static T1: [u64; 256] = [
    0x02AA_B17C_F7E9_0C5E, /*    0 */
    0xAC42_4B03_E243_A8EC, /*    1 */
    0x72CD_5BE3_0DD5_FCD3, /*    2 */
    0x6D01_9B93_F6F9_7F3A, /*    3 */
    0xCD99_78FF_D21F_9193, /*    4 */
    0x7573_A1C9_7080_29E2, /*    5 */
    0xB164_326B_922A_83C3, /*    6 */
    0x4688_3EEE_0491_5870, /*    7 */
    0xEAAC_E305_7103_ECE6, /*    8 */
    0xC541_69B8_08A3_535C, /*    9 */
    0x4CE7_5491_8DDE_C47C, /*   10 */
    0x0AA2_F4DF_DC0D_F40C, /*   11 */
    0x10B7_6F18_A74D_BEFA, /*   12 */
    0xC6CC_B623_5AD1_AB6A, /*   13 */
    0x1372_6121_572F_E2FF, /*   14 */
    0x1A48_8C6F_199D_921E, /*   15 */
    0x4BC9_F9F4_DA00_07CA, /*   16 */
    0x26F5_E6F6_E852_41C7, /*   17 */
    0x8590_79DB_EA59_47B6, /*   18 */
    0x4F18_85C5_C99E_8C92, /*   19 */
    0xD78E_761E_A96F_864B, /*   20 */
    0x8E36_428C_52B5_C17D, /*   21 */
    0x69CF_6827_3730_63C1, /*   22 */
    0xB607_C93D_9BB4_C56E, /*   23 */
    0x7D82_0E76_0E76_B5EA, /*   24 */
    0x645C_9CC6_F07F_DC42, /*   25 */
    0xBF38_A078_2433_42E0, /*   26 */
    0x5F6B_343C_9D2E_7D04, /*   27 */
    0xF2C2_8AEB_600B_0EC6, /*   28 */
    0x6C0E_D85F_7254_BCAC, /*   29 */
    0x7159_2281_A4DB_4FE5, /*   30 */
    0x1967_FA69_CE0F_ED9F, /*   31 */
    0xFD52_93F8_B965_45DB, /*   32 */
    0xC879_E9D7_F2A7_600B, /*   33 */
    0x8602_4892_0193_194E, /*   34 */
    0xA4F9_533B_2D9C_C0B3, /*   35 */
    0x9053_836C_1595_7613, /*   36 */
    0xDB6D_CF8A_FC35_7BF1, /*   37 */
    0x18BE_EA7A_7A37_0F57, /*   38 */
    0x0371_17CA_50B9_9066, /*   39 */
    0x6AB3_0A97_7442_4A35, /*   40 */
    0xF4E9_2F02_E325_249B, /*   41 */
    0x7739_DB07_061C_CAE1, /*   42 */
    0xD8F3_B49C_ECA4_2A05, /*   43 */
    0xBD56_BE3F_5138_2F73, /*   44 */
    0x45FA_ED58_43B0_BB28, /*   45 */
    0x1C81_3D5C_11BF_1F83, /*   46 */
    0x8AF0_E4B6_D75F_A169, /*   47 */
    0x33EE_18A4_87AD_9999, /*   48 */
    0x3C26_E8EA_B1C9_4410, /*   49 */
    0xB510_102B_C0A8_22F9, /*   50 */
    0x141E_EF31_0CE6_123B, /*   51 */
    0xFC65_B900_59DD_B154, /*   52 */
    0xE015_8640_C5E0_E607, /*   53 */
    0x884E_0798_26C3_A3CF, /*   54 */
    0x930D_0D95_23C5_35FD, /*   55 */
    0x3563_8D75_4E9A_2B00, /*   56 */
    0x4085_FCCF_4046_9DD5, /*   57 */
    0xC4B1_7AD2_8BE2_3A4C, /*   58 */
    0xCAB2_F0FC_6A3E_6A2E, /*   59 */
    0x2860_971A_6B94_3FCD, /*   60 */
    0x3DDE_6EE2_12E3_0446, /*   61 */
    0x6222_F32A_E017_65AE, /*   62 */
    0x5D55_0BB5_4783_08FE, /*   63 */
    0xA9EF_A98D_A0ED_A22A, /*   64 */
    0xC351_A716_86C4_0DA7, /*   65 */
    0x1105_586D_9C86_7C84, /*   66 */
    0xDCFF_EE85_FDA2_2853, /*   67 */
    0xCCFB_D026_2C5E_EF76, /*   68 */
    0xBAF2_94CB_8990_D201, /*   69 */
    0xE694_64F5_2AFA_D975, /*   70 */
    0x94B0_13AF_DF13_3E14, /*   71 */
    0x06A7_D1A3_2823_C958, /*   72 */
    0x6F95_FE51_30F6_1119, /*   73 */
    0xD92A_B34E_462C_06C0, /*   74 */
    0xED7B_DE33_887C_71D2, /*   75 */
    0x7974_6D6E_6518_393E, /*   76 */
    0x5BA4_1938_5D71_3329, /*   77 */
    0x7C1B_A6B9_48A9_7564, /*   78 */
    0x3198_7C19_7BFD_AC67, /*   79 */
    0xDE6C_23C4_4B05_3D02, /*   80 */
    0x581C_49FE_D002_D64D, /*   81 */
    0xDD47_4D63_3826_1571, /*   82 */
    0xAA45_46C3_E473_D062, /*   83 */
    0x928F_CE34_9455_F860, /*   84 */
    0x4816_1BBA_CAAB_94D9, /*   85 */
    0x6391_2430_770E_6F68, /*   86 */
    0x6EC8_A5E6_02C6_641C, /*   87 */
    0x8728_2515_337D_DD2B, /*   88 */
    0x2CDA_6B42_034B_701B, /*   89 */
    0xB03D_37C1_81CB_096D, /*   90 */
    0xE108_4382_66C7_1C6F, /*   91 */
    0x2B31_80C7_EB51_B255, /*   92 */
    0xDF92_B82F_96C0_8BBC, /*   93 */
    0x5C68_C8C0_A632_F3BA, /*   94 */
    0x5504_CC86_1C3D_0556, /*   95 */
    0xABBF_A4E5_5FB2_6B8F, /*   96 */
    0x4184_8B0A_B3BA_CEB4, /*   97 */
    0xB334_A273_AA44_5D32, /*   98 */
    0xBCA6_96F0_A85A_D881, /*   99 */
    0x24F6_EC65_B528_D56C, /*  100 */
    0x0CE1_512E_90F4_524A, /*  101 */
    0x4E9D_D79D_5506_D35A, /*  102 */
    0x2589_05FA_C6CE_9779, /*  103 */
    0x2019_295B_3E10_9B33, /*  104 */
    0xF8A9_478B_73A0_54CC, /*  105 */
    0x2924_F2F9_3441_7EB0, /*  106 */
    0x3993_357D_536D_1BC4, /*  107 */
    0x38A8_1AC2_1DB6_FF8B, /*  108 */
    0x47C4_FBF1_7D60_16BF, /*  109 */
    0x1E0F_AADD_7667_E3F5, /*  110 */
    0x7ABC_FF62_938B_EB96, /*  111 */
    0xA78D_AD94_8FC1_79C9, /*  112 */
    0x8F1F_98B7_2911_E50D, /*  113 */
    0x61E4_8EAE_2712_1A91, /*  114 */
    0x4D62_F7AD_3185_9808, /*  115 */
    0xECEB_A345_EF5C_EAEB, /*  116 */
    0xF5CE_B25E_BC96_84CE, /*  117 */
    0xF633_E20C_B7F7_6221, /*  118 */
    0xA32C_DF06_AB82_93E4, /*  119 */
    0x985A_202C_A5EE_2CA4, /*  120 */
    0xCF0B_8447_CC8A_8FB1, /*  121 */
    0x9F76_5244_9798_59A3, /*  122 */
    0xA8D5_16B1_A124_0017, /*  123 */
    0x0BD7_BA3E_BB5D_C726, /*  124 */
    0xE54B_CA55_B86A_DB39, /*  125 */
    0x1D7A_3AFD_6C47_8063, /*  126 */
    0x519E_C608_E766_9EDD, /*  127 */
    0x0E57_15A2_D149_AA23, /*  128 */
    0x177D_4571_848F_F194, /*  129 */
    0xEEB5_5F32_4101_4C22, /*  130 */
    0x0F5E_5CA1_3A6E_2EC2, /*  131 */
    0x8029_927B_75F5_C361, /*  132 */
    0xAD13_9FAB_C3D6_E436, /*  133 */
    0x0D5D_F1A9_4CCF_402F, /*  134 */
    0x3E8B_D948_BEA5_DFC8, /*  135 */
    0xA5A0_D357_BD3F_F77E, /*  136 */
    0xA2D1_2E25_1F74_F645, /*  137 */
    0x66FD_9E52_5E81_A082, /*  138 */
    0x2E0C_90CE_7F68_7A49, /*  139 */
    0xC2E8_BCBE_BA97_3BC5, /*  140 */
    0x0000_01BC_E509_745F, /*  141 */
    0x4237_77BB_E6DA_B3D6, /*  142 */
    0xD166_1C7E_AEF0_6EB5, /*  143 */
    0xA178_1F35_4DAA_CFD8, /*  144 */
    0x2D11_284A_2B16_AFFC, /*  145 */
    0xF1FC_4F67_FA89_1D1F, /*  146 */
    0x73EC_C25D_CB92_0ADA, /*  147 */
    0xAE61_0C22_C2A1_2651, /*  148 */
    0x96E0_A810_D356_B78A, /*  149 */
    0x5A9A_381F_2FE7_870F, /*  150 */
    0xD5AD_62ED_E94E_5530, /*  151 */
    0xD225_E5E8_368D_1427, /*  152 */
    0x6597_7B70_C7AF_4631, /*  153 */
    0x99F8_89B2_DE39_D74F, /*  154 */
    0x233F_30BF_54E1_D143, /*  155 */
    0x9A96_75D3_D9A6_3C97, /*  156 */
    0x5470_554F_F334_F9A8, /*  157 */
    0x166A_CB74_4A4F_5688, /*  158 */
    0x70C7_4CAA_B2E4_AEAD, /*  159 */
    0xF0D0_9164_6F29_4D12, /*  160 */
    0x57B8_2A89_6840_31D1, /*  161 */
    0xEFD9_5A5A_61BE_0B6B, /*  162 */
    0x2FBD_12E9_69F2_F29A, /*  163 */
    0x9BD3_7013_FEFF_9FE8, /*  164 */
    0x3F9B_0404_D608_5A06, /*  165 */
    0x4940_C1F3_166C_FE15, /*  166 */
    0x0954_2C4D_CDF3_DEFB, /*  167 */
    0xB4C5_2183_85CD_5CE3, /*  168 */
    0xC935_B7DC_4462_A641, /*  169 */
    0x3417_F8A6_8ED3_B63F, /*  170 */
    0xB809_5929_5B21_5B40, /*  171 */
    0xF99C_DAEF_3B8C_8572, /*  172 */
    0x018C_0614_F8FC_B95D, /*  173 */
    0x1B14_ACCD_1A3A_CDF3, /*  174 */
    0x84D4_71F2_00BB_732D, /*  175 */
    0xC1A3_110E_95E8_DA16, /*  176 */
    0x430A_7220_BF1A_82B8, /*  177 */
    0xB77E_090D_39DF_210E, /*  178 */
    0x5EF4_BD9F_3CD0_5E9D, /*  179 */
    0x9D4F_F6DA_7E57_A444, /*  180 */
    0xDA1D_60E1_83D4_A5F8, /*  181 */
    0xB287_C384_1799_8E47, /*  182 */
    0xFE3E_DC12_1BB3_1886, /*  183 */
    0xC7FE_3CCC_980C_CBEF, /*  184 */
    0xE46F_B590_189B_FD03, /*  185 */
    0x3732_FD46_9A4C_57DC, /*  186 */
    0x7EF7_00A0_7CF1_AD65, /*  187 */
    0x59C6_4468_A31D_8859, /*  188 */
    0x762F_B0B4_D45B_61F6, /*  189 */
    0x155B_AED0_9904_7718, /*  190 */
    0x6875_5E4C_3D50_BAA6, /*  191 */
    0xE921_4E7F_22D8_B4DF, /*  192 */
    0x2ADD_BF53_2EAC_95F4, /*  193 */
    0x32AE_3909_B4BD_0109, /*  194 */
    0x834D_F537_B08E_3450, /*  195 */
    0xFA20_9DA8_4220_728D, /*  196 */
    0x9E69_1D9B_9EFE_23F7, /*  197 */
    0x0446_D288_C4AE_8D7F, /*  198 */
    0x7B4C_C524_E169_785B, /*  199 */
    0x21D8_7F01_35CA_1385, /*  200 */
    0xCEBB_400F_137B_8AA5, /*  201 */
    0x272E_2B66_5807_96BE, /*  202 */
    0x3612_2641_25C2_B0DE, /*  203 */
    0x0577_02BD_AD1E_FBB2, /*  204 */
    0xD4BA_BB8E_ACF8_4BE9, /*  205 */
    0x9158_3139_641B_C67B, /*  206 */
    0x8BDC_2DE0_8036_E024, /*  207 */
    0x603C_8156_F49F_68ED, /*  208 */
    0xF7D2_36F7_DBEF_5111, /*  209 */
    0x9727_C459_8AD2_1E80, /*  210 */
    0xA08A_0896_670A_5FD7, /*  211 */
    0xCB4A_8F43_09EB_A9CB, /*  212 */
    0x81AF_564B_0F70_36A1, /*  213 */
    0xC0B9_9AA7_7819_9ABD, /*  214 */
    0x959F_1EC8_3FC8_E952, /*  215 */
    0x8C50_5077_794A_81B9, /*  216 */
    0x3ACA_AF8F_0563_38F0, /*  217 */
    0x07B4_3F50_627A_6778, /*  218 */
    0x4A44_AB49_F5EC_CC77, /*  219 */
    0x3BC3_D6E4_B679_EE98, /*  220 */
    0x9CC0_D4D1_CF14_108C, /*  221 */
    0x4406_C00B_206B_C8A0, /*  222 */
    0x82A1_8854_C8D7_2D89, /*  223 */
    0x67E3_66B3_5C3C_432C, /*  224 */
    0xB923_DD61_102B_37F2, /*  225 */
    0x56AB_2779_D884_271D, /*  226 */
    0xBE83_E1B0_FF15_25AF, /*  227 */
    0xFB7C_65D4_217E_49A9, /*  228 */
    0x6BDB_E0E7_6D48_E7D4, /*  229 */
    0x08DF_8287_45D9_179E, /*  230 */
    0x22EA_6A9A_DD53_BD34, /*  231 */
    0xE36E_141C_5622_200A, /*  232 */
    0x7F80_5D1B_8CB7_50EE, /*  233 */
    0xAFE5_C7A5_9F58_E837, /*  234 */
    0xE27F_996A_4FB1_C23C, /*  235 */
    0xD386_7DFB_0775_F0D0, /*  236 */
    0xD0E6_73DE_6E88_891A, /*  237 */
    0x123A_EB9E_AFB8_6C25, /*  238 */
    0x30F1_D5D5_C145_B895, /*  239 */
    0xBB43_4A2D_EE72_69E7, /*  240 */
    0x78CB_67EC_F931_FA38, /*  241 */
    0xF33B_0372_323B_BF9C, /*  242 */
    0x52D6_6336_FB27_9C74, /*  243 */
    0x505F_33AC_0AFB_4EAA, /*  244 */
    0xE8A5_CD99_A2CC_E187, /*  245 */
    0x5349_7480_1E2D_30BB, /*  246 */
    0x8D2D_5711_D587_6D90, /*  247 */
    0x1F1A_4128_91BC_038E, /*  248 */
    0xD6E2_E71D_82E5_6648, /*  249 */
    0x7403_6C3A_4977_32B7, /*  250 */
    0x89B6_7ED9_6361_F5AB, /*  251 */
    0xFFED_95D8_F1EA_02A2, /*  252 */
    0xE72B_3BD6_1464_D43D, /*  253 */
    0xA630_0F17_0BDC_4820, /*  254 */
    0xEBC1_8760_ED78_A77A, /*  255 */
];
static T2: [u64; 256] = [
    0xE6A6_BE5A_05A1_2138, /*  256 */
    0xB5A1_22A5_B4F8_7C98, /*  257 */
    0x563C_6089_140B_6990, /*  258 */
    0x4C46_CB2E_391F_5DD5, /*  259 */
    0xD932_ADDB_C9B7_9434, /*  260 */
    0x08EA_70E4_2015_AFF5, /*  261 */
    0xD765_A667_3E47_8CF1, /*  262 */
    0xC4FB_757E_AB27_8D99, /*  263 */
    0xDF11_C686_2D6E_0692, /*  264 */
    0xDDEB_84F1_0D7F_3B16, /*  265 */
    0x6F2E_F604_A665_EA04, /*  266 */
    0x4A8E_0F0F_F0E0_DFB3, /*  267 */
    0xA5ED_EEF8_3DBC_BA51, /*  268 */
    0xFC4F_0A2A_0EA4_371E, /*  269 */
    0xE83E_1DA8_5CB3_8429, /*  270 */
    0xDC8F_F882_BA1B_1CE2, /*  271 */
    0xCD45_505E_8353_E80D, /*  272 */
    0x18D1_9A00_D4DB_0717, /*  273 */
    0x34A0_CFED_A5F3_8101, /*  274 */
    0x0BE7_7E51_8887_CAF2, /*  275 */
    0x1E34_1438_B3C4_5136, /*  276 */
    0xE057_97F4_9089_CCF9, /*  277 */
    0xFFD2_3F9D_F259_1D14, /*  278 */
    0x543D_DA22_8595_C5CD, /*  279 */
    0x661F_81FD_9905_2A33, /*  280 */
    0x8736_E641_DB0F_7B76, /*  281 */
    0x1522_7725_418E_5307, /*  282 */
    0xE25F_7F46_162E_B2FA, /*  283 */
    0x48A8_B212_6C13_D9FE, /*  284 */
    0xAFDC_5417_92E7_6EEA, /*  285 */
    0x03D9_12BF_C6D1_898F, /*  286 */
    0x31B1_AAFA_1B83_F51B, /*  287 */
    0xF1AC_2796_E42A_B7D9, /*  288 */
    0x40A3_A7D7_FCD2_EBAC, /*  289 */
    0x1056_136D_0AFB_BCC5, /*  290 */
    0x7889_E1DD_9A6D_0C85, /*  291 */
    0xD335_2578_2A79_74AA, /*  292 */
    0xA7E2_5D09_078A_C09B, /*  293 */
    0xBD41_38B3_EAC6_EDD0, /*  294 */
    0x920A_BFBE_71EB_9E70, /*  295 */
    0xA2A5_D0F5_4FC2_625C, /*  296 */
    0xC054_E36B_0B12_90A3, /*  297 */
    0xF6DD_59FF_62FE_932B, /*  298 */
    0x3537_3545_11A8_AC7D, /*  299 */
    0xCA84_5E91_72FA_DCD4, /*  300 */
    0x84F8_2B60_329D_20DC, /*  301 */
    0x79C6_2CE1_CD67_2F18, /*  302 */
    0x8B09_A2AD_D124_642C, /*  303 */
    0xD0C1_E96A_19D9_E726, /*  304 */
    0x5A78_6A9B_4BA9_500C, /*  305 */
    0x0E02_0336_634C_43F3, /*  306 */
    0xC17B_474A_EB66_D822, /*  307 */
    0x6A73_1AE3_EC9B_AAC2, /*  308 */
    0x8226_667A_E084_0258, /*  309 */
    0x67D4_5676_91CA_ECA5, /*  310 */
    0x1D94_155C_4875_ADB5, /*  311 */
    0x6D00_FD98_5B81_3FDF, /*  312 */
    0x5128_6EFC_B774_CD06, /*  313 */
    0x5E88_3447_1FA7_44AF, /*  314 */
    0xF72C_A0AE_E761_AE2E, /*  315 */
    0xBE40_E4CD_AEE8_E09A, /*  316 */
    0xE997_0BBB_5118_F665, /*  317 */
    0x726E_4BEB_33DF_1964, /*  318 */
    0x703B_0007_2919_9762, /*  319 */
    0x4631_D816_F5EF_30A7, /*  320 */
    0xB880_B5B5_1504_A6BE, /*  321 */
    0x6417_93C3_7ED8_4B6C, /*  322 */
    0x7B21_ED77_F6E9_7D96, /*  323 */
    0x7763_0631_2EF9_6B73, /*  324 */
    0xAE52_8948_E86F_F3F4, /*  325 */
    0x53DB_D7F2_86A3_F8F8, /*  326 */
    0x16CA_DCE7_4CFC_1063, /*  327 */
    0x005C_19BD_FA52_C6DD, /*  328 */
    0x6886_8F5D_64D4_6AD3, /*  329 */
    0x3A9D_512C_CF1E_186A, /*  330 */
    0x367E_62C2_3856_60AE, /*  331 */
    0xE359_E7EA_77DC_B1D7, /*  332 */
    0x526C_0773_749A_BE6E, /*  333 */
    0x735A_E5F9_D09F_734B, /*  334 */
    0x493F_C7CC_8A55_8BA8, /*  335 */
    0xB0B9_C153_3041_AB45, /*  336 */
    0x3219_58BA_470A_59BD, /*  337 */
    0x852D_B00B_5F46_C393, /*  338 */
    0x9120_9B2B_D336_B0E5, /*  339 */
    0x6E60_4F7D_659E_F19F, /*  340 */
    0xB99A_8AE2_782C_CB24, /*  341 */
    0xCCF5_2AB6_C814_C4C7, /*  342 */
    0x4727_D9AF_BE11_727B, /*  343 */
    0x7E95_0D0C_0121_B34D, /*  344 */
    0x756F_4356_70AD_471F, /*  345 */
    0xF5AD_D442_615A_6849, /*  346 */
    0x4E87_E099_80B9_957A, /*  347 */
    0x2ACF_A1DF_50AE_E355, /*  348 */
    0xD898_263A_FD2F_D556, /*  349 */
    0xC8F4_924D_D80C_8FD6, /*  350 */
    0xCF99_CA3D_754A_173A, /*  351 */
    0xFE47_7BAC_AF91_BF3C, /*  352 */
    0xED53_71F6_D690_C12D, /*  353 */
    0x831A_5C28_5E68_7094, /*  354 */
    0xC5D3_C90A_3708_A0A4, /*  355 */
    0x0F7F_9037_17D0_6580, /*  356 */
    0x19F9_BB13_B8FD_F27F, /*  357 */
    0xB1BD_6F1B_4D50_2843, /*  358 */
    0x1C76_1BA3_8FFF_4012, /*  359 */
    0x0D15_30C4_E2E2_1F3B, /*  360 */
    0x8943_CE69_A737_2C8A, /*  361 */
    0xE518_4E11_FEB5_CE66, /*  362 */
    0x618B_DB80_BD73_6621, /*  363 */
    0x7D29_BAD6_8B57_4D0B, /*  364 */
    0x81BB_613E_25E6_FE5B, /*  365 */
    0x071C_9C10_BC07_913F, /*  366 */
    0xC7BE_EB79_09AC_2D97, /*  367 */
    0xC3E5_8D35_3BC5_D757, /*  368 */
    0xEB01_7892_F38F_61E8, /*  369 */
    0xD4EF_FB9C_9B1C_C21A, /*  370 */
    0x9972_7D26_F494_F7AB, /*  371 */
    0xA3E0_63A2_956B_3E03, /*  372 */
    0x9D4A_8B9A_4AA0_9C30, /*  373 */
    0x3F6A_B7D5_0009_0FB4, /*  374 */
    0x9CC0_F2A0_5726_8AC0, /*  375 */
    0x3DEE_9D2D_EDBF_42D1, /*  376 */
    0x330F_49C8_7960_A972, /*  377 */
    0xC6B2_7202_8742_1B41, /*  378 */
    0x0AC5_9EC0_7C00_369C, /*  379 */
    0xEF4E_AC49_CB35_3425, /*  380 */
    0xF450_244E_EF01_29D8, /*  381 */
    0x8ACC_46E5_CAF4_DEB6, /*  382 */
    0x2FFE_AB63_9892_63F7, /*  383 */
    0x8F7C_B9FE_5D7A_4578, /*  384 */
    0x5BD8_F764_4E63_4635, /*  385 */
    0x427A_7315_BF2D_C900, /*  386 */
    0x17D0_C4AA_2125_261C, /*  387 */
    0x3992_486C_9351_8E50, /*  388 */
    0xB4CB_FEE0_A2D7_D4C3, /*  389 */
    0x7C75_D620_2C5D_DD8D, /*  390 */
    0xDBC2_95D8_E35B_6C61, /*  391 */
    0x60B3_69D3_0203_2B19, /*  392 */
    0xCE42_685F_DCE4_4132, /*  393 */
    0x06F3_DDB9_DDF6_5610, /*  394 */
    0x8EA4_D21D_B5E1_48F0, /*  395 */
    0x20B0_FCE6_2FCD_496F, /*  396 */
    0x2C1B_9123_58B0_EE31, /*  397 */
    0xB283_17B8_18F5_A308, /*  398 */
    0xA89C_1E18_9CA6_D2CF, /*  399 */
    0x0C6B_1857_6AAA_DBC8, /*  400 */
    0xB65D_EAA9_1299_FAE3, /*  401 */
    0xFB2B_794B_7F10_27E7, /*  402 */
    0x04E4_317F_443B_5BEB, /*  403 */
    0x4B85_2D32_5939_D0A6, /*  404 */
    0xD5AE_6BEE_FB20_7FFC, /*  405 */
    0x3096_82B2_81C7_D374, /*  406 */
    0xBAE3_09A1_94C3_B475, /*  407 */
    0x8CC3_F97B_13B4_9F05, /*  408 */
    0x98A9_422F_F829_3967, /*  409 */
    0x244B_16B0_1076_FF7C, /*  410 */
    0xF8BF_571C_663D_67EE, /*  411 */
    0x1F0D_6758_EEE3_0DA1, /*  412 */
    0xC9B6_11D9_7ADE_B9B7, /*  413 */
    0xB7AF_D588_7B6C_57A2, /*  414 */
    0x6290_AE84_6B98_4FE1, /*  415 */
    0x94DF_4CDE_ACC1_A5FD, /*  416 */
    0x058A_5BD1_C548_3AFF, /*  417 */
    0x6316_6CC1_42BA_3C37, /*  418 */
    0x8DB8_526E_B2F7_6F40, /*  419 */
    0xE108_8003_6F0D_6D4E, /*  420 */
    0x9E05_23C9_971D_311D, /*  421 */
    0x45EC_2824_CC7C_D691, /*  422 */
    0x575B_8359_E623_82C9, /*  423 */
    0xFA9E_400D_C488_9995, /*  424 */
    0xD182_3ECB_4572_1568, /*  425 */
    0xDAFD_983B_8206_082F, /*  426 */
    0xAA7D_2908_2386_A8CB, /*  427 */
    0x269F_CD44_03B8_7588, /*  428 */
    0x1B91_F5F7_28BD_D1E0, /*  429 */
    0xE466_9F39_0402_01F6, /*  430 */
    0x7A1D_7C21_8CF0_4ADE, /*  431 */
    0x6562_3C29_D79C_E5CE, /*  432 */
    0x2368_4490_96C0_0BB1, /*  433 */
    0xAB9B_F187_9DA5_03BA, /*  434 */
    0xBC23_ECB1_A458_058E, /*  435 */
    0x9A58_DF01_BB40_1ECC, /*  436 */
    0xA070_E868_A85F_143D, /*  437 */
    0x4FF1_8830_7DF2_239E, /*  438 */
    0x14D5_65B4_1A64_1183, /*  439 */
    0xEE13_3374_5270_1602, /*  440 */
    0x950E_3DCF_3F28_5E09, /*  441 */
    0x5993_0254_B9C8_0953, /*  442 */
    0x3BF2_9940_8930_DA6D, /*  443 */
    0xA955_943F_5369_1387, /*  444 */
    0xA15E_DECA_A9CB_8784, /*  445 */
    0x2914_2127_352B_E9A0, /*  446 */
    0x76F0_371F_FF4E_7AFB, /*  447 */
    0x0239_F450_274F_2228, /*  448 */
    0xBB07_3AF0_1D5E_868B, /*  449 */
    0xBFC8_0571_C10E_96C1, /*  450 */
    0xD267_0885_6822_2E23, /*  451 */
    0x9671_A3D4_8E80_B5B0, /*  452 */
    0x55B5_D38A_E193_BB81, /*  453 */
    0x693A_E2D0_A18B_04B8, /*  454 */
    0x5C48_B4EC_ADD5_335F, /*  455 */
    0xFD74_3B19_4916_A1CA, /*  456 */
    0x2577_0181_34BE_98C4, /*  457 */
    0xE779_87E8_3C54_A4AD, /*  458 */
    0x28E1_1014_DA33_E1B9, /*  459 */
    0x270C_C59E_226A_A213, /*  460 */
    0x7149_5F75_6D1A_5F60, /*  461 */
    0x9BE8_53FB_60AF_EF77, /*  462 */
    0xADC7_86A7_F744_3DBF, /*  463 */
    0x0904_4561_73B2_9A82, /*  464 */
    0x58BC_7A66_C232_BD5E, /*  465 */
    0xF306_558C_673A_C8B2, /*  466 */
    0x41F6_39C6_B6C9_772A, /*  467 */
    0x216D_EFE9_9FDA_35DA, /*  468 */
    0x1164_0CC7_1C7B_E615, /*  469 */
    0x93C4_3694_565C_5527, /*  470 */
    0xEA03_8E62_4677_7839, /*  471 */
    0xF9AB_F3CE_5A3E_2469, /*  472 */
    0x741E_768D_0FD3_12D2, /*  473 */
    0x0144_B883_CED6_52C6, /*  474 */
    0xC20B_5A5B_A33F_8552, /*  475 */
    0x1AE6_9633_C343_5A9D, /*  476 */
    0x97A2_8CA4_088C_FDEC, /*  477 */
    0x8824_A43C_1E96_F420, /*  478 */
    0x3761_2FA6_6EEE_A746, /*  479 */
    0x6B4C_B165_F9CF_0E5A, /*  480 */
    0x43AA_1C06_A0AB_FB4A, /*  481 */
    0x7F4D_C26F_F162_796B, /*  482 */
    0x6CBA_CC8E_54ED_9B0F, /*  483 */
    0xA6B7_FFEF_D2BB_253E, /*  484 */
    0x2E25_BC95_B0A2_9D4F, /*  485 */
    0x86D6_A58B_DEF1_388C, /*  486 */
    0xDED7_4AC5_76B6_F054, /*  487 */
    0x8030_BDBC_2B45_805D, /*  488 */
    0x3C81_AF70_E94D_9289, /*  489 */
    0x3EFF_6DDA_9E31_00DB, /*  490 */
    0xB38D_C39F_DFCC_8847, /*  491 */
    0x1238_8552_8D17_B87E, /*  492 */
    0xF2DA_0ED2_40B1_B642, /*  493 */
    0x44CE_FADC_D54B_F9A9, /*  494 */
    0x1312_200E_433C_7EE6, /*  495 */
    0x9FFC_C84F_3A78_C748, /*  496 */
    0xF0CD_1F72_2485_76BB, /*  497 */
    0xEC69_7405_3638_CFE4, /*  498 */
    0x2BA7_B67C_0CEC_4E4C, /*  499 */
    0xAC2F_4DF3_E5CE_32ED, /*  500 */
    0xCB33_D143_26EA_4C11, /*  501 */
    0xA4E9_044C_C77E_58BC, /*  502 */
    0x5F51_3293_D934_FCEF, /*  503 */
    0x5DC9_6455_06E5_5444, /*  504 */
    0x50DE_418F_317D_E40A, /*  505 */
    0x388C_B31A_69DD_E259, /*  506 */
    0x2DB4_A834_5582_0A86, /*  507 */
    0x9010_A91E_8471_1AE9, /*  508 */
    0x4DF7_F0B7_B149_8371, /*  509 */
    0xD62A_2EAB_C097_7179, /*  510 */
    0x22FA_C097_AA8D_5C0E, /*  511 */
];
static T3: [u64; 256] = [
    0xF49F_CC2F_F1DA_F39B, /*  512 */
    0x487F_D5C6_6FF2_9281, /*  513 */
    0xE8A3_0667_FCDC_A83F, /*  514 */
    0x2C9B_4BE3_D2FC_CE63, /*  515 */
    0xDA3F_F74B_93FB_BBC2, /*  516 */
    0x2FA1_65D2_FE70_BA66, /*  517 */
    0xA103_E279_970E_93D4, /*  518 */
    0xBECD_EC77_B0E4_5E71, /*  519 */
    0xCFB4_1E72_3985_E497, /*  520 */
    0xB70A_AA02_5EF7_5017, /*  521 */
    0xD423_09F0_3840_B8E0, /*  522 */
    0x8EFC_1AD0_3589_8579, /*  523 */
    0x96C6_920B_E2B2_ABC5, /*  524 */
    0x66AF_4163_375A_9172, /*  525 */
    0x2174_ABDC_CA71_27FB, /*  526 */
    0xB33C_CEA6_4A72_FF41, /*  527 */
    0xF04A_4933_0830_66A5, /*  528 */
    0x8D97_0ACD_D728_9AF5, /*  529 */
    0x8F96_E8E0_31C8_C25E, /*  530 */
    0xF3FE_C022_7687_5D47, /*  531 */
    0xEC7B_F310_0561_90DD, /*  532 */
    0xF5AD_B0AE_BB0F_1491, /*  533 */
    0x9B50_F885_0FD5_8892, /*  534 */
    0x4975_4883_58B7_4DE8, /*  535 */
    0xA335_4FF6_9153_1C61, /*  536 */
    0x0702_BBE4_81D2_C6EE, /*  537 */
    0x89FB_2405_7DED_ED98, /*  538 */
    0xAC30_7513_8596_E902, /*  539 */
    0x1D2D_3580_1727_72ED, /*  540 */
    0xEB73_8FC2_8E6B_C30D, /*  541 */
    0x5854_EF8F_6304_4326, /*  542 */
    0x9E5C_5232_5ADD_3BBE, /*  543 */
    0x90AA_53CF_325C_4623, /*  544 */
    0xC1D2_4D51_349D_D067, /*  545 */
    0x2051_CFEE_A69E_A624, /*  546 */
    0x1322_0F0A_862E_7E4F, /*  547 */
    0xCE39_3994_04E0_4864, /*  548 */
    0xD9C4_2CA4_7086_FCB7, /*  549 */
    0x685A_D223_8A03_E7CC, /*  550 */
    0x0664_84B2_AB2F_F1DB, /*  551 */
    0xFE9D_5D70_EFBF_79EC, /*  552 */
    0x5B13_B9DD_9C48_1854, /*  553 */
    0x15F0_D475_ED15_09AD, /*  554 */
    0x0BEB_CD06_0EC7_9851, /*  555 */
    0xD58C_6791_183A_B7F8, /*  556 */
    0xD118_7C50_52F3_EEE4, /*  557 */
    0xC95D_1192_E54E_82FF, /*  558 */
    0x86EE_A14C_B9AC_6CA2, /*  559 */
    0x3485_BEB1_5367_7D5D, /*  560 */
    0xDD19_1D78_1F8C_492A, /*  561 */
    0xF608_66BA_A784_EBF9, /*  562 */
    0x518F_643B_A2D0_8C74, /*  563 */
    0x8852_E956_E108_7C22, /*  564 */
    0xA768_CB8D_C410_AE8D, /*  565 */
    0x3804_7726_BFEC_8E1A, /*  566 */
    0xA677_38B4_CD3B_45AA, /*  567 */
    0xAD16_691C_EC0D_DE19, /*  568 */
    0xC6D4_3193_8046_2E07, /*  569 */
    0xC5A5_876D_0BA6_1938, /*  570 */
    0x16B9_FA1F_A58F_D840, /*  571 */
    0x188A_B117_3CA7_4F18, /*  572 */
    0xABDA_2F98_C99C_021F, /*  573 */
    0x3E05_80AB_134A_E816, /*  574 */
    0x5F3B_05B7_7364_5ABB, /*  575 */
    0x2501_A2BE_5575_F2F6, /*  576 */
    0x1B2F_7400_4E7E_8BA9, /*  577 */
    0x1CD7_5803_71E8_D953, /*  578 */
    0x7F6E_D895_6276_4E30, /*  579 */
    0xB159_26FF_596F_003D, /*  580 */
    0x9F65_293D_A8C5_D6B9, /*  581 */
    0x6ECE_F04D_D690_F84C, /*  582 */
    0x4782_275F_FF33_AF88, /*  583 */
    0xE414_3308_3F82_0801, /*  584 */
    0xFD0D_FE40_9A1A_F9B5, /*  585 */
    0x4325_A334_2CDB_396B, /*  586 */
    0x8AE7_7E62_B301_B252, /*  587 */
    0xC36F_9E9F_6655_615A, /*  588 */
    0x8545_5A2D_92D3_2C09, /*  589 */
    0xF2C7_DEA9_4947_7485, /*  590 */
    0x63CF_B4C1_33A3_9EBA, /*  591 */
    0x83B0_40CC_6EBC_5462, /*  592 */
    0x3B94_54C8_FDB3_26B0, /*  593 */
    0x56F5_6A9E_87FF_D78C, /*  594 */
    0x2DC2_940D_99F4_2BC6, /*  595 */
    0x98F7_DF09_6B09_6E2D, /*  596 */
    0x19A6_E01E_3AD8_52BF, /*  597 */
    0x42A9_9CCB_DBD4_B40B, /*  598 */
    0xA599_98AF_45E9_C559, /*  599 */
    0x3662_95E8_07D9_3186, /*  600 */
    0x6B48_181B_FAA1_F773, /*  601 */
    0x1FEC_57E2_157A_0A1D, /*  602 */
    0x4667_446A_F620_1AD5, /*  603 */
    0xE615_EBCA_CFB0_F075, /*  604 */
    0xB8F3_1F4F_6829_0778, /*  605 */
    0x2271_3ED6_CE22_D11E, /*  606 */
    0x3057_C1A7_2EC3_C93B, /*  607 */
    0xCB46_ACC3_7C3F_1F2F, /*  608 */
    0xDBB8_93FD_02AA_F50E, /*  609 */
    0x331F_D92E_600B_9FCF, /*  610 */
    0xA498_F961_48EA_3AD6, /*  611 */
    0xA8D8_426E_8B6A_83EA, /*  612 */
    0xA089_B274_B773_5CDC, /*  613 */
    0x87F6_B373_1E52_4A11, /*  614 */
    0x1188_08E5_CBC9_6749, /*  615 */
    0x9906_E4C7_B19B_D394, /*  616 */
    0xAFED_7F7E_9B24_A20C, /*  617 */
    0x6509_EADE_EB36_44A7, /*  618 */
    0x6C1E_F1D3_E8EF_0EDE, /*  619 */
    0xB9C9_7D43_E979_8FB4, /*  620 */
    0xA2F2_D784_740C_28A3, /*  621 */
    0x7B84_9647_6197_566F, /*  622 */
    0x7A5B_E3E6_B65F_069D, /*  623 */
    0xF963_30ED_78BE_6F10, /*  624 */
    0xEEE6_0DE7_7A07_6A15, /*  625 */
    0x2B4B_EE4A_A08B_9BD0, /*  626 */
    0x6A56_A63E_C7B8_894E, /*  627 */
    0x0212_1359_BA34_FEF4, /*  628 */
    0x4CBF_99F8_2837_03FC, /*  629 */
    0x3980_7135_0CAF_30C8, /*  630 */
    0xD0A7_7A89_F017_687A, /*  631 */
    0xF1C1_A9EB_9E42_3569, /*  632 */
    0x8C79_7628_2DEE_8199, /*  633 */
    0x5D17_37A5_DD1F_7ABD, /*  634 */
    0x4F53_433C_09A9_FA80, /*  635 */
    0xFA8B_0C53_DF7C_A1D9, /*  636 */
    0x3FD9_DCBC_886C_CB77, /*  637 */
    0xC040_917C_A91B_4720, /*  638 */
    0x7DD0_0142_F9D1_DCDF, /*  639 */
    0x8476_FC1D_4F38_7B58, /*  640 */
    0x23F8_E7C5_F331_6503, /*  641 */
    0x032A_2244_E7E3_7339, /*  642 */
    0x5C87_A5D7_50F5_A74B, /*  643 */
    0x082B_4CC4_3698_992E, /*  644 */
    0xDF91_7BEC_B858_F63C, /*  645 */
    0x3270_B8FC_5BF8_6DDA, /*  646 */
    0x10AE_72BB_29B5_DD76, /*  647 */
    0x576A_C94E_7700_362B, /*  648 */
    0x1AD1_12DA_C61E_FB8F, /*  649 */
    0x691B_C30E_C5FA_A427, /*  650 */
    0xFF24_6311_CC32_7143, /*  651 */
    0x3142_368E_30E5_3206, /*  652 */
    0x7138_0E31_E02C_A396, /*  653 */
    0x958D_5C96_0AAD_76F1, /*  654 */
    0xF8D6_F430_C16D_A536, /*  655 */
    0xC8FF_D13F_1BE7_E1D2, /*  656 */
    0x7578_AE66_004D_DBE1, /*  657 */
    0x0583_3F01_067B_E646, /*  658 */
    0xBB34_B5AD_3BFE_586D, /*  659 */
    0x095F_34C9_A12B_97F0, /*  660 */
    0x247A_B645_25D6_0CA8, /*  661 */
    0xDCDB_C6F3_0174_77D1, /*  662 */
    0x4A2E_14D4_DECA_D24D, /*  663 */
    0xBDB5_E6D9_BE0A_1EEB, /*  664 */
    0x2A7E_70F7_7943_01AB, /*  665 */
    0xDEF4_2D8A_2705_40FD, /*  666 */
    0x0107_8EC0_A34C_22C1, /*  667 */
    0xE5DE_511A_F4C1_6387, /*  668 */
    0x7EBB_3A52_BD9A_330A, /*  669 */
    0x7769_7857_AA7D_6435, /*  670 */
    0x004E_8316_03AE_4C32, /*  671 */
    0xE7A2_1020_AD78_E312, /*  672 */
    0x9D41_A70C_6AB4_20F2, /*  673 */
    0x28E0_6C18_EA11_41E6, /*  674 */
    0xD2B2_8CBD_984F_6B28, /*  675 */
    0x26B7_5F6C_446E_9D83, /*  676 */
    0xBA47_568C_4D41_8D7F, /*  677 */
    0xD80B_ADBF_E618_3D8E, /*  678 */
    0x0E20_6D7F_5F16_6044, /*  679 */
    0xE258_A439_11CB_CA3E, /*  680 */
    0x723A_1746_B21D_C0BC, /*  681 */
    0xC7CA_A854_F5D7_CDD3, /*  682 */
    0x7CAC_3288_3D26_1D9C, /*  683 */
    0x7690_C264_23BA_942C, /*  684 */
    0x17E5_5524_4780_42B8, /*  685 */
    0xE0BE_4776_56A2_389F, /*  686 */
    0x4D28_9B5E_67AB_2DA0, /*  687 */
    0x4486_2B9C_8FBB_FD31, /*  688 */
    0xB47C_C804_9D14_1365, /*  689 */
    0x822C_1B36_2B91_C793, /*  690 */
    0x4EB1_4655_FB13_DFD8, /*  691 */
    0x1ECB_BA07_14E2_A97B, /*  692 */
    0x6143_459D_5CDE_5F14, /*  693 */
    0x53A8_FBF1_D5F0_AC89, /*  694 */
    0x97EA_04D8_1C5E_5B00, /*  695 */
    0x6221_81A8_D4FD_B3F3, /*  696 */
    0xE9BC_D341_572A_1208, /*  697 */
    0x1411_2586_43CC_E58A, /*  698 */
    0x9144_C5FE_A4C6_E0A4, /*  699 */
    0x0D33_D065_65CF_620F, /*  700 */
    0x54A4_8D48_9F21_9CA1, /*  701 */
    0xC43E_5EAC_6D63_C821, /*  702 */
    0xA972_8B3A_7277_0DAF, /*  703 */
    0xD793_4E7B_20DF_87EF, /*  704 */
    0xE355_03B6_1A3E_86E5, /*  705 */
    0xCAE3_21FB_C819_D504, /*  706 */
    0x129A_50B3_AC60_BFA6, /*  707 */
    0xCD5E_68EA_7E9F_B6C3, /*  708 */
    0xB01C_9019_9483_B1C7, /*  709 */
    0x3DE9_3CD5_C295_376C, /*  710 */
    0xAED5_2EDF_2AB9_AD13, /*  711 */
    0x2E60_F512_C0A0_7884, /*  712 */
    0xBC3D_86A3_E362_10C9, /*  713 */
    0x3526_9D9B_1639_51CE, /*  714 */
    0x0C7D_6E2A_D0CD_B5FA, /*  715 */
    0x59E8_6297_D87F_5733, /*  716 */
    0x298E_F221_898D_B0E7, /*  717 */
    0x5500_0029_D1A5_AA7E, /*  718 */
    0x8BC0_8AE1_B506_1B45, /*  719 */
    0xC2C3_1C2B_6C92_703A, /*  720 */
    0x94CC_596B_AF25_EF42, /*  721 */
    0x0A1D_73DB_2254_0456, /*  722 */
    0x04B6_A0F9_D9C4_179A, /*  723 */
    0xEFFD_AFA2_AE3D_3C60, /*  724 */
    0xF7C8_075B_B494_96C4, /*  725 */
    0x9CC5_C714_1D1C_D4E3, /*  726 */
    0x78BD_1638_218E_5534, /*  727 */
    0xB2F1_1568_F850_246A, /*  728 */
    0xEDFA_BCFA_9502_BC29, /*  729 */
    0x796C_E5F2_DA23_051B, /*  730 */
    0xAAE1_28B0_DC93_537C, /*  731 */
    0x3A49_3DA0_EE4B_29AE, /*  732 */
    0xB5DF_6B2C_4168_95D7, /*  733 */
    0xFCAB_BD25_122D_7F37, /*  734 */
    0x7081_0B58_105D_C4B1, /*  735 */
    0xE10F_DD37_F788_2A90, /*  736 */
    0x524D_CAB5_518A_3F5C, /*  737 */
    0x3C9E_8587_8451_255B, /*  738 */
    0x4029_8281_19BD_34E2, /*  739 */
    0x74A0_5B6F_5D3C_ECCB, /*  740 */
    0xB610_0215_42E1_3ECA, /*  741 */
    0x0FF9_79D1_2F59_E2AC, /*  742 */
    0x6037_DA27_E4F9_CC50, /*  743 */
    0x5E92_975A_0DF1_847D, /*  744 */
    0xD66D_E190_D3E6_23FE, /*  745 */
    0x5032_D6B8_7B56_8048, /*  746 */
    0x9A36_B7CE_8235_216E, /*  747 */
    0x8027_2A7A_24F6_4B4A, /*  748 */
    0x93EF_ED8B_8C69_16F7, /*  749 */
    0x37DD_BFF4_4CCE_1555, /*  750 */
    0x4B95_DB5D_4B99_BD25, /*  751 */
    0x92D3_FDA1_6981_2FC0, /*  752 */
    0xFB1A_4A9A_9066_0BB6, /*  753 */
    0x730C_1969_46A4_B9B2, /*  754 */
    0x81E2_89AA_7F49_DA68, /*  755 */
    0x6466_9A0F_83B1_A05F, /*  756 */
    0x27B3_FF7D_9644_F48B, /*  757 */
    0xCC6B_615C_8DB6_75B3, /*  758 */
    0x674F_20B9_BCEB_BE95, /*  759 */
    0x6F31_2382_7565_5982, /*  760 */
    0x5AE4_8871_3E45_CF05, /*  761 */
    0xBF61_9F99_54C2_1157, /*  762 */
    0xEABA_C460_40A8_EAE9, /*  763 */
    0x454C_6FE9_F2C0_C1CD, /*  764 */
    0x419C_F649_6412_691C, /*  765 */
    0xD3DC_3BEF_265B_0F70, /*  766 */
    0x6D0E_60F5_C357_8A9E, /*  767 */
];
static T4: [u64; 256] = [
    0x5B0E_6085_2632_3C55, /*  768 */
    0x1A46_C1A9_FA1B_59F5, /*  769 */
    0xA9E2_45A1_7C4C_8FFA, /*  770 */
    0x65CA_5159_DB29_55D7, /*  771 */
    0x05DB_0A76_CE35_AFC2, /*  772 */
    0x81EA_C77E_A911_3D45, /*  773 */
    0x528E_F88A_B6AC_0A0D, /*  774 */
    0xA09E_A253_597B_E3FF, /*  775 */
    0x430D_DFB3_AC48_CD56, /*  776 */
    0xC4B3_A67A_F45C_E46F, /*  777 */
    0x4ECE_CFD8_FBE2_D05E, /*  778 */
    0x3EF5_6F10_B399_35F0, /*  779 */
    0x0B22_D682_9CD6_19C6, /*  780 */
    0x17FD_460A_74DF_2069, /*  781 */
    0x6CF8_CC8E_8510_ED40, /*  782 */
    0xD6C8_24BF_3A6E_CAA7, /*  783 */
    0x6124_3D58_1A81_7049, /*  784 */
    0x048B_ACB6_BBC1_63A2, /*  785 */
    0xD9A3_8AC2_7D44_CC32, /*  786 */
    0x7FDD_FF5B_AAF4_10AB, /*  787 */
    0xAD6D_495A_A804_824B, /*  788 */
    0xE1A6_A74F_2D8C_9F94, /*  789 */
    0xD4F7_8512_35DE_E8E3, /*  790 */
    0xFD4B_7F88_6540_D893, /*  791 */
    0x247C_2004_2AA4_BFDA, /*  792 */
    0x096E_A1C5_17D1_327C, /*  793 */
    0xD569_66B4_361A_6685, /*  794 */
    0x277D_A5C3_1221_057D, /*  795 */
    0x94D5_9893_A43A_CFF7, /*  796 */
    0x64F0_C51C_CDC0_2281, /*  797 */
    0x3D33_BCC4_FF61_89DB, /*  798 */
    0xE005_CB18_4CE6_6AF1, /*  799 */
    0xFF5C_CD1D_1DB9_9BEA, /*  800 */
    0xB0B8_54A7_FE42_980F, /*  801 */
    0x7BD4_6A6A_718D_4B9F, /*  802 */
    0xD10F_A8CC_22A5_FD8C, /*  803 */
    0xD314_8495_2BE4_BD31, /*  804 */
    0xC7FA_975F_CB24_3847, /*  805 */
    0x4886_ED1E_5846_C407, /*  806 */
    0x28CD_DB79_1EB7_0B04, /*  807 */
    0xC2B0_0BE2_F573_417F, /*  808 */
    0x5C95_9045_2180_F877, /*  809 */
    0x7A6B_DDFF_F370_EB00, /*  810 */
    0xCE50_9E38_D6D9_D6A4, /*  811 */
    0xEBEB_0F00_647F_A702, /*  812 */
    0x1DCC_06CF_7660_6F06, /*  813 */
    0xE4D9_F28B_A286_FF0A, /*  814 */
    0xD85A_305D_C918_C262, /*  815 */
    0x475B_1D87_3222_5F54, /*  816 */
    0x2D4F_B516_68CC_B5FE, /*  817 */
    0xA679_B9D9_D72B_BA20, /*  818 */
    0x5384_1C0D_912D_43A5, /*  819 */
    0x3B7E_AA48_BF12_A4E8, /*  820 */
    0x781E_0E47_F22F_1DDF, /*  821 */
    0xEFF2_0CE6_0AB5_0973, /*  822 */
    0x20D2_61D1_9DFF_B742, /*  823 */
    0x16A1_2B03_062A_2E39, /*  824 */
    0x1960_EB22_3965_0495, /*  825 */
    0x251C_16FE_D50E_B8B8, /*  826 */
    0x9AC0_C330_F826_016E, /*  827 */
    0xED15_2665_953E_7671, /*  828 */
    0x02D6_3194_A636_9570, /*  829 */
    0x5074_F083_94B1_C987, /*  830 */
    0x70BA_598C_90B2_5CE1, /*  831 */
    0x794A_1581_0B97_42F6, /*  832 */
    0x0D59_25E9_FCAF_8C6C, /*  833 */
    0x3067_716C_D868_744E, /*  834 */
    0x910A_B077_E8D7_731B, /*  835 */
    0x6A61_BBDB_5AC4_2F61, /*  836 */
    0x9351_3EFB_F085_1567, /*  837 */
    0xF494_724B_9E83_E9D5, /*  838 */
    0xE887_E198_5C09_648D, /*  839 */
    0x34B1_D3C6_7537_0CFD, /*  840 */
    0xDC35_E433_BC0D_255D, /*  841 */
    0xD0AA_B842_3413_1BE0, /*  842 */
    0x0804_2A50_B48B_7EAF, /*  843 */
    0x9997_C4EE_44A3_AB35, /*  844 */
    0x829A_7B49_2017_99D0, /*  845 */
    0x263B_8307_B7C5_4441, /*  846 */
    0x752F_95F4_FD6A_6CA6, /*  847 */
    0x9272_1740_2C08_C6E5, /*  848 */
    0x2A8A_B754_A795_D9EE, /*  849 */
    0xA442_F755_2F72_943D, /*  850 */
    0x2C31_334E_1978_1208, /*  851 */
    0x4FA9_8D7C_EAEE_6291, /*  852 */
    0x55C3_862F_665D_B309, /*  853 */
    0xBD06_1017_5D53_B1F3, /*  854 */
    0x46FE_6CB8_4041_3F27, /*  855 */
    0x3FE0_3792_DF0C_FA59, /*  856 */
    0xCFE7_0037_2EB8_5E8F, /*  857 */
    0xA7BE_29E7_ADBC_E118, /*  858 */
    0xE544_EE5C_DE84_31DD, /*  859 */
    0x8A78_1B1B_41F1_873E, /*  860 */
    0xA5C9_4C78_A0D2_F0E7, /*  861 */
    0x3941_2E28_77B6_0728, /*  862 */
    0xA126_5EF3_AFC9_A62C, /*  863 */
    0xBCC2_770C_6A25_06C5, /*  864 */
    0x3AB6_6DD5_DCE1_CE12, /*  865 */
    0xE654_99D0_4A67_5B37, /*  866 */
    0x7D8F_5234_81BF_D216, /*  867 */
    0x0F6F_64FC_EC15_F389, /*  868 */
    0x74EF_BE61_8B5B_13C8, /*  869 */
    0xACDC_82B7_1427_3E1D, /*  870 */
    0xDD40_BFE0_0319_9D17, /*  871 */
    0x37E9_9257_E7E0_61F8, /*  872 */
    0xFA52_6269_0477_5AAA, /*  873 */
    0x8BBB_F63A_463D_56F9, /*  874 */
    0xF001_3F15_43A2_6E64, /*  875 */
    0xA830_7E9F_879E_C898, /*  876 */
    0xCC4C_27A4_1501_77CC, /*  877 */
    0x1B43_2F2C_CA1D_3348, /*  878 */
    0xDE1D_1F8F_9F6F_A013, /*  879 */
    0x6066_02A0_47A7_DDD6, /*  880 */
    0xD237_AB64_CC1C_B2C7, /*  881 */
    0x9B93_8E72_25FC_D1D3, /*  882 */
    0xEC4E_0370_8E0F_F476, /*  883 */
    0xFEB2_FBDA_3D03_C12D, /*  884 */
    0xAE0B_CED2_EE43_889A, /*  885 */
    0x22CB_8923_EBFB_4F43, /*  886 */
    0x6936_0D01_3CF7_396D, /*  887 */
    0x855E_3602_D2D4_E022, /*  888 */
    0x0738_05BA_D01F_784C, /*  889 */
    0x33E1_7A13_3852_F546, /*  890 */
    0xDF48_7405_8AC7_B638, /*  891 */
    0xBA92_B29C_678A_A14A, /*  892 */
    0x0CE8_9FC7_6CFA_ADCD, /*  893 */
    0x5F9D_4E09_0833_9E34, /*  894 */
    0xF1AF_E929_1F59_23B9, /*  895 */
    0x6E34_80F6_0F4A_265F, /*  896 */
    0xEEBF_3A2A_B29B_841C, /*  897 */
    0xE219_38A8_8F91_B4AD, /*  898 */
    0x57DF_EFF8_45C6_D3C3, /*  899 */
    0x2F00_6B0B_F62C_AAF2, /*  900 */
    0x62F4_79EF_6F75_EE78, /*  901 */
    0x11A5_5AD4_1C89_16A9, /*  902 */
    0xF229_D290_84FE_D453, /*  903 */
    0x42F1_C27B_16B0_00E6, /*  904 */
    0x2B1F_7674_9823_C074, /*  905 */
    0x4B76_ECA3_C274_5360, /*  906 */
    0x8C98_F463_B916_91BD, /*  907 */
    0x14BC_C93C_F1AD_E66A, /*  908 */
    0x8885_213E_6D45_8397, /*  909 */
    0x8E17_7DF0_274D_4711, /*  910 */
    0xB49B_73B5_503F_2951, /*  911 */
    0x1016_8168_C3F9_6B6B, /*  912 */
    0x0E3D_963B_63CA_B0AE, /*  913 */
    0x8DFC_4B56_55A1_DB14, /*  914 */
    0xF789_F135_6E14_DE5C, /*  915 */
    0x683E_68AF_4E51_DAC1, /*  916 */
    0xC9A8_4F9D_8D4B_0FD9, /*  917 */
    0x3691_E03F_52A0_F9D1, /*  918 */
    0x5ED8_6E46_E187_8E80, /*  919 */
    0x3C71_1A0E_99D0_7150, /*  920 */
    0x5A08_65B2_0C4E_9310, /*  921 */
    0x56FB_FC1F_E4F0_682E, /*  922 */
    0xEA8D_5DE3_105E_DF9B, /*  923 */
    0x71AB_FDB1_2379_187A, /*  924 */
    0x2EB9_9DE1_BEE7_7B9C, /*  925 */
    0x21EC_C0EA_33CF_4523, /*  926 */
    0x59A4_D752_1805_C7A1, /*  927 */
    0x3896_F5EB_56AE_7C72, /*  928 */
    0xAA63_8F3D_B18F_75DC, /*  929 */
    0x9F39_358D_ABE9_808E, /*  930 */
    0xB7DE_FA91_C00B_72AC, /*  931 */
    0x6B55_41FD_6249_2D92, /*  932 */
    0x6DC6_DEE8_F92E_4D5B, /*  933 */
    0x353F_57AB_C4BE_EA7E, /*  934 */
    0x7357_69D6_DA56_90CE, /*  935 */
    0x0A23_4AA6_4239_1484, /*  936 */
    0xF6F9_5080_28F8_0D9D, /*  937 */
    0xB8E3_19A2_7AB3_F215, /*  938 */
    0x31AD_9C11_5134_1A4D, /*  939 */
    0x773C_22A5_7BEF_5805, /*  940 */
    0x45C7_561A_0796_8633, /*  941 */
    0xF913_DA9E_249D_BE36, /*  942 */
    0xDA65_2D9B_78A6_4C68, /*  943 */
    0x4C27_A97F_3BC3_34EF, /*  944 */
    0x7662_1220_E66B_17F4, /*  945 */
    0x9677_4389_9ACD_7D0B, /*  946 */
    0xF3EE_5BCA_E0ED_6782, /*  947 */
    0x409F_7536_00C8_79FC, /*  948 */
    0x06D0_9A39_B592_6DB6, /*  949 */
    0x6F83_AEB0_317A_C588, /*  950 */
    0x01E6_CA4A_8638_1F21, /*  951 */
    0x66FF_3462_D19F_3025, /*  952 */
    0x7220_7C24_DDFD_3BFB, /*  953 */
    0x4AF6_B6D3_E2EC_E2EB, /*  954 */
    0x9C99_4DBE_C7EA_08DE, /*  955 */
    0x49AC_E597_B09A_8BC4, /*  956 */
    0xB38C_4766_CF07_97BA, /*  957 */
    0x131B_9373_C57C_2A75, /*  958 */
    0xB182_2CCE_6193_1E58, /*  959 */
    0x9D75_55B9_09BA_1C0C, /*  960 */
    0x127F_AFDD_937D_11D2, /*  961 */
    0x29DA_3BAD_C66D_92E4, /*  962 */
    0xA2C1_D571_54C2_ECBC, /*  963 */
    0x58C5_134D_82F6_FE24, /*  964 */
    0x1C3A_E351_5B62_274F, /*  965 */
    0xE907_C82E_01CB_8126, /*  966 */
    0xF8ED_0919_13E3_7FCB, /*  967 */
    0x3249_D8F9_C800_46C9, /*  968 */
    0x80CF_9BED_E388_FB63, /*  969 */
    0x1881_539A_116C_F19E, /*  970 */
    0x5103_F3F7_6BD5_2457, /*  971 */
    0x15B7_E6F5_AE47_F7A8, /*  972 */
    0xDBD7_C6DE_D47E_9CCF, /*  973 */
    0x44E5_5C41_0228_BB1A, /*  974 */
    0xB647_D425_5EDB_4E99, /*  975 */
    0x5D11_882B_B8AA_FC30, /*  976 */
    0xF509_8BBB_29D3_212A, /*  977 */
    0x8FB5_EA14_E902_96B3, /*  978 */
    0x677B_9421_57DD_025A, /*  979 */
    0xFB58_E7C0_A390_ACB5, /*  980 */
    0x89D3_674C_83BD_4A01, /*  981 */
    0x9E2D_A4DF_4BF3_B93B, /*  982 */
    0xFCC4_1E32_8CAB_4829, /*  983 */
    0x03F3_8C96_BA58_2C52, /*  984 */
    0xCAD1_BDBD_7FD8_5DB2, /*  985 */
    0xBBB4_42C1_6082_AE83, /*  986 */
    0xB95F_E86B_A5DA_9AB0, /*  987 */
    0xB22E_0467_3771_A93F, /*  988 */
    0x8453_58C9_4931_52D8, /*  989 */
    0xBE2A_4886_97B4_541E, /*  990 */
    0x95A2_DC2D_D38E_6966, /*  991 */
    0xC02C_11AC_923C_852B, /*  992 */
    0x2388_B199_0DF2_A87B, /*  993 */
    0x7C80_08FA_1B4F_37BE, /*  994 */
    0x1F70_D0C8_4D54_E503, /*  995 */
    0x5490_ADEC_7ECE_57D4, /*  996 */
    0x002B_3C27_D906_3A3A, /*  997 */
    0x7EAE_A384_8030_A2BF, /*  998 */
    0xC602_326D_ED20_03C0, /*  999 */
    0x83A7_287D_69A9_4086, /* 1000 */
    0xC57A_5FCB_30F5_7A8A, /* 1001 */
    0xB568_44E4_79EB_E779, /* 1002 */
    0xA373_B40F_05DC_BCE9, /* 1003 */
    0xD71A_786E_8857_0EE2, /* 1004 */
    0x879C_BACD_BDE8_F6A0, /* 1005 */
    0x976A_D1BC_C164_A32F, /* 1006 */
    0xAB21_E25E_9666_D78B, /* 1007 */
    0x9010_63AA_E5E5_C33C, /* 1008 */
    0x9818_B344_4869_8D90, /* 1009 */
    0xE364_87AE_3E1E_8ABB, /* 1010 */
    0xAFBD_F931_893B_DCB4, /* 1011 */
    0x6345_A0DC_5FBB_D519, /* 1012 */
    0x8628_FE26_9B94_65CA, /* 1013 */
    0x1E5D_0160_3F9C_51EC, /* 1014 */
    0x4DE4_4006_A150_49B7, /* 1015 */
    0xBF6C_70E5_F776_CBB1, /* 1016 */
    0x4112_18F2_EF55_2BED, /* 1017 */
    0xCB0C_0708_705A_36A3, /* 1018 */
    0xE74D_1475_4F98_6044, /* 1019 */
    0xCD56_D943_0EA8_280E, /* 1020 */
    0xC125_91D7_535F_5065, /* 1021 */
    0xC832_23F1_720A_EF96, /* 1022 */
    0xC3A0_396F_7363_A51F, /* 1023 */
];
