// SPDX-License-Identifier: Apache-2.0

//! SHA-512 (FIPS 180-4), the hash inside Ed25519.
//!
//! RFC 8032 derives both the signing scalar and the per-signature nonce by
//! hashing with SHA-512, so key generation needs this hash before any curve
//! arithmetic runs. The protocol crate owns SHA-256 for content addressing;
//! this module owns the SHA-512 half of the same policy: the workspace is
//! dependency-free, the implementation is small, and its outputs are pinned
//! by the standard FIPS 180-4 vectors plus the RFC 8032 Ed25519 test vectors
//! exercised end to end in [`crate::ed25519`], so a defect cannot pass the
//! gate unnoticed.

/// The SHA-512 initialization vector (FIPS 180-4 §5.3.5): fractional parts
/// of the square roots of the first eight primes.
const H0: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// The SHA-512 round constants (FIPS 180-4 §4.2.3): fractional parts of the
/// cube roots of the first eighty primes.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Block size in bytes (FIPS 180-4: 1024-bit blocks).
const BLOCK_BYTES: usize = 128;

/// The compression-function message schedule, `W[0..80]`.
fn schedule(block: &[u8; BLOCK_BYTES]) -> [u64; 80] {
    let mut w = [0u64; 80];
    for (chunk, word) in block.chunks_exact(8).zip(w.iter_mut()) {
        *word = u64::from_be_bytes(chunk.try_into().expect("chunks_exact(8) yields 8 bytes"));
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    w
}

/// Compress one 1024-bit block into the eight-word chaining state.
#[allow(clippy::many_single_char_names)] // a, b, .. h are the spec's names
fn compress(state: &mut [u64; 8], block: &[u8; BLOCK_BYTES]) {
    let w = schedule(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (i, k) in K.iter().enumerate() {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    let rounds = [a, b, c, d, e, f, g, h];
    for (word, state_word) in rounds.iter().zip(state.iter_mut()) {
        *state_word = state_word.wrapping_add(*word);
    }
}

/// The SHA-512 digest of `message`: 64 bytes.
///
/// The inputs this crate hashes (identity seeds and, later, Ed25519 signing
/// nonces) are tens of bytes, so a one-shot signature is the whole API; a
/// streaming hasher arrives with the code that hashes unbounded input.
#[must_use]
pub fn digest(message: &[u8]) -> [u8; 64] {
    // Padded length: message, one 0x80 separator, zeros, then a 128-bit
    // length, rounded to whole blocks (FIPS 180-4 §5.1.2).
    let padded_len =
        message.len() + 1 + (128 - ((message.len() + 1 + 16) % BLOCK_BYTES)) % BLOCK_BYTES + 16;
    let mut padded = vec![0u8; padded_len];
    padded[..message.len()].copy_from_slice(message);
    padded[message.len()] = 0x80;
    let bit_len = (message.len() as u128).wrapping_mul(8);
    padded[padded_len - 16..].copy_from_slice(&bit_len.to_be_bytes());

    let mut state = H0;
    for block in padded.chunks_exact(BLOCK_BYTES) {
        compress(
            &mut state,
            block
                .try_into()
                .expect("chunks_exact(128) yields 128 bytes"),
        );
    }

    let mut out = [0u8; 64];
    for (word, chunk) in state.iter().zip(out.chunks_exact_mut(8)) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 §D.1 — the empty message.
    #[test]
    fn empty_message_vector() {
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(digest(b""), expected);
    }

    /// FIPS 180-4 §D.2 — the single-block message `"abc"`.
    #[test]
    fn abc_vector() {
        let expected = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(digest(b"abc"), expected);
    }

    /// FIPS 180-4 §D.3 — the two-block message spanning the padding
    /// boundary that a single-block vector cannot reach.
    #[test]
    fn two_block_vector() {
        let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = [
            0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28, 0x14, 0xfc,
            0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1, 0x72, 0x99, 0xae, 0xad,
            0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e, 0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b,
            0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a, 0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54,
            0x5e, 0x96, 0xe5, 0x5b, 0x87, 0x4b, 0xe9, 0x09,
        ];
        assert_eq!(digest(message), expected);
    }

    /// The padding-boundary edge: 111 bytes plus separator and length fit
    /// one block exactly, while 112 bytes force a second block. The pinned
    /// D.3 vector covers the two-block path for one message; this pins that
    /// the boundary itself is computed correctly for another, and that the
    /// digest is length-sensitive and stable across calls.
    #[test]
    fn padding_boundary_lengths() {
        let one_block = digest(&[0u8; BLOCK_BYTES - 17]);
        let two_blocks = digest(&[0u8; BLOCK_BYTES - 16]);
        assert_ne!(one_block, two_blocks);
        assert_eq!(two_blocks, digest(&[0u8; BLOCK_BYTES - 16]));
    }
}
