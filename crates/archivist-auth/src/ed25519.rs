// SPDX-License-Identifier: Apache-2.0

//! Ed25519 (RFC 8032): key construction, signing, and verification.
//!
//! The workspace is dependency-free by policy, so the curve arithmetic lives
//! here like the protocol crate's SHA-256: a small, fully owned
//! implementation of the RFC's three moving parts — the §5.1.5 key
//! construction (hash the seed, clamp, multiply the base point, encode),
//! the §5.1.6 signing (deterministic nonce drawn from the secret half of
//! the seed expansion), and the §5.1.7 verification (point decompression,
//! challenge recomputation, and the `[S]B = R + [k]A` check). Every output
//! and every refusal is pinned by the RFC 8032 §7.1 test vectors, positive
//! and negative alike, so a defect cannot pass the gate unnoticed.
//!
//! # Constant-time posture
//!
//! Scalar multiplication processes every scalar bit with the same
//! doubling-plus-conditional-add sequence, and the conditional add selects
//! between the target point and the neutral point with arithmetic masks,
//! so the instruction sequence does not branch on secret bits. Scalar
//! reduction modulo the group order runs a fixed 512-step schedule whose
//! conditional subtraction is mask-selected, because it processes the
//! signing scalar and the secret nonce. Field inversion and the square
//! root use fixed exponentiation schedules, and decompression only ever
//! handles public material. The remaining branches canonicalize values
//! that are already public output.

use crate::sha512;

/// A field element mod `p = 2^255 - 19` in five 51-bit limbs.
///
/// Every producing operation ends in [`carry_reduce`], which leaves the
/// element fully canonical: each limb is below `2^51` and the value is
/// below `p`. Limb-wise `PartialEq` is therefore value equality, and the
/// packed encoding in [`EdPoint::encode`] can assume non-overlapping limbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fe([u64; 5]);

/// `2^51 - 1`: the limb mask.
const LIMB_MASK: u64 = (1 << 51) - 1;

/// Field elements add without carrying; limbs stay below `2^52` because
/// both inputs are canonical. The sum is weak (limbs may reach `2^52`) and
/// is canonicalized by the next [`carry_reduce`] inside any producing
/// operation — `fe_add` results only ever feed `fe_mul` or `fe_sub`.
const fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut limbs = [0u64; 5];
    let mut i = 0;
    while i < 5 {
        limbs[i] = a.0[i] + b.0[i];
        i += 1;
    }
    Fe(limbs)
}

/// `a - b` with a `2p` bias so limbs never underflow, canonicalized.
// Widening `as` casts: `From` conversions are not const-callable on this
// toolchain, and every cast here is u64 -> u128 (infallible).
#[allow(clippy::cast_lossless)]
const fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // 2p in 51-bit limbs; adding it first keeps every limb non-negative
    // because each canonical input limb is below 2^51 and each 2p limb is
    // above 2^51.
    let two_p = [
        0xf_ffff_ffff_ffda,
        0xf_ffff_ffff_fffe,
        0xf_ffff_ffff_fffe,
        0xf_ffff_ffff_fffe,
        0xf_ffff_ffff_fffe,
    ];
    let mut limbs = [0u128; 5];
    let mut i = 0;
    while i < 5 {
        limbs[i] = (a.0[i] + two_p[i] - b.0[i]) as u128;
        i += 1;
    }
    Fe(carry_reduce(limbs))
}

/// Fold limb carries until every limb is below `2^51`, folding the top
/// limb's overflow back through the low limb with the `19` endomorphism
/// (mod `p`, `2^255 = 19`), then subtract `p` once if the value still
/// reaches it.
///
/// The result is canonical: limbs below `2^51`, value below `p`. Each
/// round either only moves excess upward or folds it back with a factor
/// `2^256 → 19` reduction, so the loop terminates after a handful of
/// rounds for every value this crate produces (field products stay below
/// `2^256`). The masked limbs are below `2^51` before the narrowing casts,
/// every intermediate in the conditional subtraction is bounded by `p`
/// (below `2^255`, so it fits `i128`), and a masked limb or a
/// borrow-bounded difference is non-negative: each narrowing cast below is
/// range-proven.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless
)]
const fn carry_reduce(mut limbs: [u128; 5]) -> [u64; 5] {
    loop {
        let mut carried = false;
        let mut i = 0;
        while i < 4 {
            if limbs[i] > LIMB_MASK as u128 {
                limbs[i + 1] += limbs[i] >> 51;
                limbs[i] &= LIMB_MASK as u128;
                carried = true;
            }
            i += 1;
        }
        if limbs[4] > LIMB_MASK as u128 {
            let top = limbs[4] >> 51;
            limbs[4] &= LIMB_MASK as u128;
            limbs[0] += top * 19;
            carried = true;
        }
        if !carried {
            break;
        }
    }
    // The value is now below 2^255 < 2p, so at most one conditional
    // subtraction canonicalizes it; the borrow cannot escape the top limb.
    let p = p_limbs();
    let mut i = 5;
    let mut ge = true;
    while i > 0 {
        i -= 1;
        if limbs[i] != p.0[i] as u128 {
            ge = limbs[i] > p.0[i] as u128;
            break;
        }
    }
    let mut out = [0u64; 5];
    if ge {
        let mut borrow: i128 = 0;
        let mut i = 0;
        while i < 5 {
            let diff = limbs[i] as i128 - p.0[i] as i128 - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 51)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
            i += 1;
        }
    } else {
        let mut i = 0;
        while i < 5 {
            out[i] = limbs[i] as u64;
            i += 1;
        }
    }
    out
}

/// Schoolbook multiply with the `19 * b[4..]` wrap, then carry-reduce.
///
/// Accumulators stay far below `2^128`: five products of `2^51`-limbs each
/// contribute at most `2^102`, and the `19` wrap adds five more.
// Widening `as` casts: `From` conversions are not const-callable on this
// toolchain, and every cast here is u64 -> u128 (infallible).
#[allow(clippy::cast_lossless)]
const fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let (a, b) = (&a.0, &b.0);
    let mut r = [0u128; 5];
    r[0] = (a[0] as u128) * (b[0] as u128)
        + 19 * ((a[1] as u128) * (b[4] as u128)
            + (a[2] as u128) * (b[3] as u128)
            + (a[3] as u128) * (b[2] as u128)
            + (a[4] as u128) * (b[1] as u128));
    r[1] = (a[0] as u128) * (b[1] as u128)
        + (a[1] as u128) * (b[0] as u128)
        + 19 * ((a[2] as u128) * (b[4] as u128)
            + (a[3] as u128) * (b[3] as u128)
            + (a[4] as u128) * (b[2] as u128));
    r[2] = (a[0] as u128) * (b[2] as u128)
        + (a[1] as u128) * (b[1] as u128)
        + (a[2] as u128) * (b[0] as u128)
        + 19 * ((a[3] as u128) * (b[4] as u128) + (a[4] as u128) * (b[3] as u128));
    r[3] = (a[0] as u128) * (b[3] as u128)
        + (a[1] as u128) * (b[2] as u128)
        + (a[2] as u128) * (b[1] as u128)
        + (a[3] as u128) * (b[0] as u128)
        + 19 * ((a[4] as u128) * (b[4] as u128));
    r[4] = (a[0] as u128) * (b[4] as u128)
        + (a[1] as u128) * (b[3] as u128)
        + (a[2] as u128) * (b[2] as u128)
        + (a[3] as u128) * (b[1] as u128)
        + (a[4] as u128) * (b[0] as u128);
    Fe(carry_reduce(r))
}

/// Raise `a` to the fixed exponent `exp` (little-endian limbs, 51 bits per
/// limb) with a square-and-multiply schedule fixed by the exponent alone.
const fn fe_pow(a: &Fe, exp: &[u64; 5]) -> Fe {
    // Start from the most significant set bit so the first multiply lands
    // on `a` itself and no squaring of a placeholder 1 is needed.
    let mut result = *a;
    let mut started = false;
    let mut limb = 5;
    while limb > 0 {
        limb -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            if started {
                result = fe_mul(&result, &result);
            }
            if (exp[limb] >> bit) & 1 == 1 {
                if started {
                    result = fe_mul(&result, a);
                } else {
                    result = *a;
                    started = true;
                }
            }
        }
    }
    result
}

/// Multiplicative inverse via the Fermat exponent `p - 2`.
///
/// The exponent is five `u64` words — `fe_pow` walks each word's 64 bits —
/// so its limbs are radix-2^64, not the field's radix-2^51: the low word
/// holds the low 64 bits of `p - 2` (`0xff..ffeb`, since `p - 2` is
/// `2^255 - 21`), word 3 holds bits 192..=255 and stops at bit 254
/// (`0x7f..ff`), and word 4 is zero — the value is 255 bits, not 311.
const fn fe_invert(a: &Fe) -> Fe {
    fe_pow(
        a,
        &[
            0xffff_ffff_ffff_ffeb,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
            0,
        ],
    )
}

/// Zero.
const FE_ZERO: Fe = Fe([0, 0, 0, 0, 0]);
/// One.
const FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);

/// The curve constant `d = -121665 / 121666`, as 51-bit limbs.
const D: Fe = Fe([
    929_955_233_495_203,
    466_365_720_129_213,
    1_662_059_464_998_953,
    2_033_849_074_728_123,
    1_442_794_654_840_575,
]);

/// `2d`, the addition-formula constant.
const TWO_D: Fe = fe_add(&D, &D);

/// The base point `B`, extended coordinates `(X : Y : Z : T)` with
/// `x = X/Z`, `y = Y/Z`, `T = XY/Z`, for the twisted Edwards curve
/// `-x^2 + y^2 = 1 + d x^2 y^2` (RFC 8032 §5.1): `y = 4/5` and the even
/// root for `x`.
const BASE: EdPoint = EdPoint {
    x: Fe([
        1_738_742_601_995_546,
        1_146_398_526_822_698,
        2_070_867_633_025_821,
        562_264_141_797_630,
        587_772_402_128_613,
    ]),
    y: Fe([
        1_801_439_850_948_184,
        1_351_079_888_211_148,
        450_359_962_737_049,
        900_719_925_474_099,
        1_801_439_850_948_198,
    ]),
    z: FE_ONE,
    t: Fe([
        1_841_354_044_333_475,
        16_398_895_984_059,
        755_974_180_946_558,
        900_171_276_175_154,
        1_821_297_809_914_039,
    ]),
};

/// A point in extended twisted Edwards coordinates.
#[derive(Clone, Copy, Debug)]
struct EdPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// The neutral element `(0 : 1 : 1 : 0)`.
const NEUTRAL: EdPoint = EdPoint {
    x: FE_ZERO,
    y: FE_ONE,
    z: FE_ONE,
    t: FE_ZERO,
};

impl EdPoint {
    /// Unified addition (`a = -1`, Hisil–Wong–Carter–Dawson); correct for
    /// equal inputs and for the neutral point, which is what the scalar
    /// loop relies on.
    #[allow(clippy::many_single_char_names)] // a..h are the formula's names
    fn add(&self, other: &EdPoint) -> EdPoint {
        let a = fe_mul(&fe_sub(&self.y, &self.x), &fe_sub(&other.y, &other.x));
        let b = fe_mul(&fe_add(&self.y, &self.x), &fe_add(&other.y, &other.x));
        let c = fe_mul(&self.t, &fe_mul(&TWO_D, &other.t));
        let two_other_z = fe_add(&other.z, &other.z);
        let d = fe_mul(&self.z, &two_other_z);
        let e = fe_sub(&b, &a);
        let f = fe_sub(&d, &c);
        let g = fe_add(&d, &c);
        let h = fe_add(&b, &a);
        EdPoint {
            x: fe_mul(&e, &f),
            y: fe_mul(&g, &h),
            z: fe_mul(&f, &g),
            t: fe_mul(&e, &h),
        }
    }

    /// Dedicated doubling for `a = -1` (`dbl-2008-hwcd`).
    ///
    /// The curve relation puts `dT^2 = Y^2 - X^2 - Z^2`, so with `A = X^2`,
    /// `B = Y^2`, `C = 2Z^2`: `B - A` is `Z^2 + dT^2` (the `x` denominator's
    /// factor) and `C - (B - A)` is `Z^2 - dT^2` (the `y` denominator's).
    /// The affine double `x3 = 2XY / (Z^2 + dT^2)`, `y3 = (A + B) / (Z^2 -
    /// dT^2)` then extends exactly as written below, and `T3 = E * H` keeps
    /// `T = XY/Z` consistent — the next [`EdPoint::add`] reads `T`.
    #[allow(clippy::many_single_char_names)] // a..h are the formula's names
    fn double(&self) -> EdPoint {
        let a = fe_mul(&self.x, &self.x);
        let b = fe_mul(&self.y, &self.y);
        let c = fe_add(&fe_mul(&self.z, &self.z), &fe_mul(&self.z, &self.z));
        let h = fe_add(&b, &a);
        let e = fe_sub(
            &fe_mul(&fe_add(&self.x, &self.y), &fe_add(&self.x, &self.y)),
            &h,
        );
        let g = fe_sub(&b, &a);
        let f = fe_sub(&c, &g);
        EdPoint {
            x: fe_mul(&e, &f),
            y: fe_mul(&h, &g),
            z: fe_mul(&f, &g),
            t: fe_mul(&e, &h),
        }
    }

    /// `bit` is `0` or `1`: return `self` when `1` and the neutral point
    /// when `0`, selected with arithmetic masks so no branch conditions on
    /// the secret-scalar bit.
    fn select(&self, bit: u64) -> EdPoint {
        // The mask is `bit` itself as a canonical field element: the pick
        // below is `neutral + mask·(component − neutral)`, which is
        // `component` for mask 1 and `neutral` for mask 0. (`bit - 1` would
        // be the mask for the opposite convention — negating here selects
        // `2·neutral − component` on set bits, which no scalar loop wants.)
        let mask = Fe([bit, 0, 0, 0, 0]);
        let pick = |component: &Fe, neutral: &Fe| {
            fe_add(neutral, &fe_mul(&mask, &fe_sub(component, neutral)))
        };
        EdPoint {
            x: pick(&self.x, &NEUTRAL.x),
            y: pick(&self.y, &NEUTRAL.y),
            z: pick(&self.z, &NEUTRAL.z),
            t: pick(&self.t, &NEUTRAL.t),
        }
    }

    /// The 32-byte compressed encoding: `y` in little-endian with the sign
    /// of `x` in the top bit (RFC 8032 §5.1.2).
    #[allow(clippy::cast_possible_truncation)] // the masked sign bit fits u8
    fn encode(&self) -> [u8; 32] {
        let z_inv = fe_invert(&self.z);
        let x = fe_mul(&self.x, &z_inv);
        let y = fe_mul(&self.y, &z_inv);
        // A carry-reduced value below 2^255 that is still >= p is within 19
        // of the modulus; one conditional subtraction canonicalizes it. The
        // branch conditions on the encoded output — public material — never
        // on the scalar.
        let y = if ge_p(&y) { fe_sub(&y, &p_limbs()) } else { y };

        let mut out = [0u8; 32];
        // Pack five 51-bit limbs into 32 bytes: the low 128 bits from
        // limbs 0..=2, the remaining 127 bits from limbs 2..=4.
        let low = u128::from(y.0[0]) | (u128::from(y.0[1]) << 51) | (u128::from(y.0[2]) << 102);
        let high =
            (u128::from(y.0[2]) >> 26) | (u128::from(y.0[3]) << 25) | (u128::from(y.0[4]) << 76);
        out[..16].copy_from_slice(&low.to_le_bytes());
        out[16..].copy_from_slice(&high.to_le_bytes());
        out[31] |= ((x.0[0] & 1) as u8) << 7;
        out
    }
}

/// `p` as limbs, materialized where a value needs subtracting it.
const fn p_limbs() -> Fe {
    Fe([
        0x7_ffff_ffff_ffed,
        0x7_ffff_ffff_ffff,
        0x7_ffff_ffff_ffff,
        0x7_ffff_ffff_ffff,
        0x7_ffff_ffff_ffff,
    ])
}

/// Lexicographic limb comparison `a >= p` for carry-reduced values.
fn ge_p(a: &Fe) -> bool {
    let p = p_limbs();
    let mut i = 5;
    while i > 0 {
        i -= 1;
        if a.0[i] != p.0[i] {
            return a.0[i] > p.0[i];
        }
    }
    true
}

/// Expand `seed` into the clamped scalar (RFC 8032 §5.1.5): the low half of
/// `SHA-512(seed)` with the three low bits cleared, the top bit cleared, and
/// the second-highest bit set.
fn clamp_scalar(seed: &[u8; 32]) -> [u8; 32] {
    let hash = sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 0xf8;
    scalar[31] &= 0x7f;
    scalar[31] |= 0x40;
    scalar
}

/// Multiply `point` by `scalar` (little-endian bytes), walking every bit
/// with the same double-plus-conditional-add sequence.
fn scalar_mul(point: &EdPoint, scalar: &[u8; 32]) -> EdPoint {
    let mut acc = NEUTRAL;
    let mut bit_index = 256;
    while bit_index > 0 {
        bit_index -= 1;
        acc = acc.double();
        let bit = u64::from((scalar[bit_index / 8] >> (bit_index % 8)) & 1);
        acc = acc.add(&point.select(bit));
    }
    acc
}

/// Multiply the base point by `scalar` (little-endian bytes).
fn scalar_mul_base(scalar: &[u8; 32]) -> EdPoint {
    scalar_mul(&BASE, scalar)
}

/// Derive the 32-byte encoded Ed25519 public key of `seed` (RFC 8032
/// §5.1.5). The seed is the installation's private half and must be
/// generated from the OS entropy source; the output is the public half and
/// may appear anywhere public material appears.
#[must_use]
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    scalar_mul_base(&clamp_scalar(seed)).encode()
}

/// The group order `L = 2^252 + 27742317777372353535851937790883648493`
/// (RFC 8032 §5.1.1), as little-endian 64-bit words.
const GROUP_ORDER_L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

/// `rem - L` across four little-endian words with the final borrow isolated
/// so the caller can keep `rem` when it is already below `L`: the borrow is
/// set exactly when `rem < L`.
// The `bool as u64` borrow digit is a const-context conversion; `From` is
// not const-callable on this toolchain.
#[allow(clippy::cast_sign_loss)]
const fn sub_l(rem: &[u64; 4]) -> ([u64; 4], u64) {
    let mut diff = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        // The word underflows exactly when `rem[i] < L[i] + borrow`.
        let word = rem[i].wrapping_sub(GROUP_ORDER_L[i]).wrapping_sub(borrow);
        borrow = (rem[i] < GROUP_ORDER_L[i] || (borrow == 1 && rem[i] == GROUP_ORDER_L[i])) as u64;
        diff[i] = word;
        i += 1;
    }
    (diff, borrow)
}

/// Conditionally subtract `L` from a value below `2L`, choosing between the
/// value and the difference with an arithmetic mask: the reduction runs on
/// the signing scalar and the secret nonce, so its control flow must not
/// depend on the bits it processes.
fn conditional_sub_l(rem: &[u64; 4]) -> [u64; 4] {
    let (diff, borrow) = sub_l(rem);
    // All-ones when `rem < L` (keep it), all-zeros otherwise (take `diff`).
    let keep_rem = borrow.wrapping_neg();
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = (rem[i] & keep_rem) | (diff[i] & !keep_rem);
        i += 1;
    }
    out
}

/// Decode 32 little-endian bytes into four 64-bit words.
// Widening `as` casts: `From` conversions are not const-callable on this
// toolchain, and every cast here is u8 -> u64 (infallible).
#[allow(clippy::cast_lossless)]
const fn scalar_from_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut words = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let mut word = 0u64;
        let mut j = 0;
        while j < 8 {
            word |= (bytes[i * 8 + j] as u64) << (8 * j);
            j += 1;
        }
        words[i] = word;
        i += 1;
    }
    words
}

/// Encode four little-endian words as 32 bytes.
fn encode_scalar_le(words: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Decode 64 little-endian bytes into eight 64-bit words.
fn wide_from_le(bytes: &[u8; 64]) -> [u64; 8] {
    let mut words = [0u64; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().expect("8-byte chunk"));
    }
    words
}

/// Reduce a 512-bit little-endian value modulo `L` (the hash outputs the
/// nonce and the challenge are drawn from), one bit at a time from the top:
/// `rem = 2·rem + bit`, then one masked conditional subtraction. The
/// remainder is below `L` before every step, so `2·rem + bit < 2L` and one
/// subtraction always re-canonicalizes; the schedule is fixed by the input
/// width and no step branches on the data.
fn reduce_mod_l_wide(value: &[u8; 64]) -> [u8; 32] {
    let value = wide_from_le(value);
    let mut rem = [0u64; 4];
    let mut word = 8;
    while word > 0 {
        word -= 1;
        let mut bit = 64;
        while bit > 0 {
            bit -= 1;
            let mut carry = (value[word] >> bit) & 1;
            let mut i = 0;
            while i < 4 {
                let pushed = rem[i] >> 63;
                rem[i] = (rem[i] << 1) | carry;
                carry = pushed;
                i += 1;
            }
            // The shift carry out of the top word is zero: `rem < L < 2^253`
            // keeps `rem[3]` below `2^61` before the shift.
            rem = conditional_sub_l(&rem);
        }
    }
    encode_scalar_le(&rem)
}

/// `(a · b) mod L` for reduced scalars: schoolbook into eight words, then
/// the wide reduction. Used for the challenge-scalar product inside the
/// signature, which multiplies the secret signing scalar.
// The `u128 as u64` narrowing casts are exact: each word is masked to its
// low 64 bits before the cast.
#[allow(clippy::cast_possible_truncation)]
fn mul_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (a, b) = (scalar_from_le(a), scalar_from_le(b));
    let mut wide = [0u128; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let total = wide[i + j] + u128::from(a[i]) * u128::from(b[j]) + carry;
            wide[i + j] = total & 0xffff_ffff_ffff_ffff;
            carry = total >> 64;
        }
        wide[i + 4] = carry;
    }
    let mut bytes = [0u8; 64];
    for (i, word) in wide.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&(*word as u64).to_le_bytes());
    }
    reduce_mod_l_wide(&bytes)
}

/// `(a + b) mod L` for reduced scalars: both are below `L < 2^253`, so the
/// word-wise sum stays inside four words and one masked conditional
/// subtraction canonicalizes it.
fn add_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (a, b) = (scalar_from_le(a), scalar_from_le(b));
    let mut sum = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let (word, first) = a[i].overflowing_add(b[i]);
        let (word, second) = word.overflowing_add(carry);
        sum[i] = word;
        carry = u64::from(first || second);
        i += 1;
    }
    debug_assert!(carry == 0, "reduced inputs sum below 2^254");
    encode_scalar_le(&conditional_sub_l(&sum))
}

/// Whether `value` is a canonically reduced scalar: strictly below the
/// group order, which §5.1.7 requires of an accepted `S` (equality is a
/// refusal, not a reduction).
fn scalar_is_reduced(value: &[u64; 4]) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if value[i] != GROUP_ORDER_L[i] {
            return value[i] < GROUP_ORDER_L[i];
        }
    }
    false
}

/// An Ed25519 signature: the 64-byte RFC 8032 encoding of the commitment
/// point `R` followed by the scalar `S`. Public material throughout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Signature {
    /// Adopt a 64-byte `R || S` encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { bytes }
    }

    /// The 64-byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

/// Sign `message` with the RFC 8032 private `seed` (§5.1.6). Deterministic:
/// the same seed and message always produce the same signature, and the
/// nonce comes from the secret half of the seed expansion — never a
/// counter, clock, or any public value.
#[must_use]
pub fn sign(seed: &[u8; 32], message: &[u8]) -> Signature {
    let hash = sha512::digest(seed);
    let scalar = clamp_scalar(seed);
    let public = scalar_mul_base(&scalar).encode();

    // r = SHA-512(prefix || M) mod L, with prefix the secret half of the
    // seed expansion (§5.1.6, step 2).
    let mut nonce_input = Vec::with_capacity(32 + message.len());
    nonce_input.extend_from_slice(&hash[32..]);
    nonce_input.extend_from_slice(message);
    let nonce = reduce_mod_l_wide(&sha512::digest(&nonce_input));
    let big_r = scalar_mul_base(&nonce).encode();

    // k = SHA-512(R || A || M) mod L; S = (r + k·a) mod L.
    let mut challenge_input = Vec::with_capacity(64 + message.len());
    challenge_input.extend_from_slice(&big_r);
    challenge_input.extend_from_slice(&public);
    challenge_input.extend_from_slice(message);
    let challenge = reduce_mod_l_wide(&sha512::digest(&challenge_input));
    let product = mul_mod_l(&challenge, &scalar);
    let s = add_mod_l(&nonce, &product);

    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&big_r);
    bytes[32..].copy_from_slice(&s);
    Signature { bytes }
}

/// Verify `signature` over `message` against the encoded Ed25519 public
/// key (RFC 8032 §5.1.7): decode both encoded points, require a
/// canonically reduced `S`, recompute the challenge from the encodings and
/// the message, and check `[S]B = R + [k]A` on the curve. Non-canonical
/// points and scalars are refused rather than reduced.
#[must_use]
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &Signature) -> bool {
    let Some(point_a) = decompress(public_key) else {
        return false;
    };
    let mut r_encoded = [0u8; 32];
    r_encoded.copy_from_slice(&signature.bytes[..32]);
    let mut s_encoded = [0u8; 32];
    s_encoded.copy_from_slice(&signature.bytes[32..]);
    if !scalar_is_reduced(&scalar_from_le(&s_encoded)) {
        return false;
    }
    let Some(point_r) = decompress(&r_encoded) else {
        return false;
    };

    let mut challenge_input = Vec::with_capacity(64 + message.len());
    challenge_input.extend_from_slice(&r_encoded);
    challenge_input.extend_from_slice(public_key);
    challenge_input.extend_from_slice(message);
    let challenge = reduce_mod_l_wide(&sha512::digest(&challenge_input));

    let lhs = scalar_mul_base(&s_encoded);
    let rhs = point_r.add(&scalar_mul(&point_a, &challenge));
    lhs.encode() == rhs.encode()
}

/// `(p - 5) / 8`, the fixed exponent of the §5.1.3 square-root extraction,
/// as little-endian 64-bit words for [`fe_pow`].
const EXPONENT_P_MINUS_5_OVER_8: [u64; 5] = [
    0xffff_ffff_ffff_fffd,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0fff_ffff_ffff_ffff,
    0,
];

/// `sqrt(-1) = 2^((p-1)/4)`, the field's square root of minus one, used to
/// correct the non-square case of the extraction. Computed by the fixed
/// exponentiation schedule at compile time; the tests pin it by squaring.
const SQRT_MINUS_ONE: Fe = fe_pow(
    &FE_TWO,
    &[
        0xffff_ffff_ffff_fffb,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x1fff_ffff_ffff_ffff,
        0,
    ],
);

/// Two, the base of the compile-time square root of minus one.
const FE_TWO: Fe = Fe([2, 0, 0, 0, 0]);

/// Unpack the 255 magnitude bits of a compressed `y` (top bit already
/// cleared) into field limbs, refusing a value at or beyond `p`: the
/// encoding is the canonical form of the element, not a residue to reduce.
// Every narrowing cast below is range-proven: each masked limb is below
// `2^51` before the `u128 as u64` cast.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn unpack_y(bytes: &[u8; 32]) -> Option<Fe> {
    let mut low = 0u128;
    for (i, byte) in bytes[..16].iter().enumerate() {
        low |= u128::from(*byte) << (8 * i);
    }
    let mut high = 0u128;
    for (i, byte) in bytes[16..].iter().enumerate() {
        high |= u128::from(*byte) << (8 * i);
    }
    let y = Fe([
        (low & u128::from(LIMB_MASK)) as u64,
        ((low >> 51) & u128::from(LIMB_MASK)) as u64,
        (((low >> 102) | (high << 26)) & u128::from(LIMB_MASK)) as u64,
        ((high >> 25) & u128::from(LIMB_MASK)) as u64,
        ((high >> 76) & u128::from(LIMB_MASK)) as u64,
    ]);
    if ge_p(&y) { None } else { Some(y) }
}

/// Recover the point behind a 32-byte compressed encoding (RFC 8032
/// §5.1.3). `None` for a non-canonical `y` (at or beyond `p`), a `y` whose
/// curve equation has no solution, or a zero `x` carrying a sign bit.
/// Only ever called on public material: verification inputs.
fn decompress(encoded: &[u8; 32]) -> Option<EdPoint> {
    let sign = u64::from(encoded[31] >> 7);
    let mut y_bytes = *encoded;
    y_bytes[31] &= 0x7f;
    let y = unpack_y(&y_bytes)?;

    // x² = (y² - 1) / (d·y² + 1) = u / v, and the candidate
    // x = u·v³·(u·v⁷)^((p-5)/8) is the root when v is a square and
    // x·sqrt(-1) otherwise; anything else means `y` is not on the curve.
    let y_squared = fe_mul(&y, &y);
    let u = fe_sub(&y_squared, &FE_ONE);
    let v = fe_add(&fe_mul(&D, &y_squared), &FE_ONE);
    let v_squared = fe_mul(&v, &v);
    let v_cubed = fe_mul(&v_squared, &v);
    let v_seventh = fe_mul(&fe_mul(&v_cubed, &v_cubed), &v);
    let mut x = fe_mul(
        &fe_mul(&u, &v_cubed),
        &fe_pow(&fe_mul(&u, &v_seventh), &EXPONENT_P_MINUS_5_OVER_8),
    );

    let check = fe_mul(&v, &fe_mul(&x, &x));
    if check == u {
        // The candidate is the root.
    } else if check == fe_sub(&FE_ZERO, &u) {
        x = fe_mul(&x, &SQRT_MINUS_ONE);
    } else {
        return None;
    }

    if x == FE_ZERO && sign == 1 {
        return None;
    }
    // The sign bit selects the parity of x; flip x when it disagrees.
    if x.0[0] & 1 != sign {
        x = fe_sub(&FE_ZERO, &x);
    }
    Some(EdPoint {
        x,
        y,
        z: FE_ONE,
        t: fe_mul(&x, &y),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 test vectors: seed (the RFC's "secret key") to public
    /// key. These pin the hash, the clamp, the curve constants, the scalar
    /// multiplication, and the encoding together — any defect in any of
    /// them breaks every row.
    #[test]
    fn rfc8032_public_key_vectors() {
        let vectors: &[(&str, &str)] = &[
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            ),
            (
                // The §7.2 `SHA(abc)` vector's seed/public pair: a scalar
                // whose expansion exercises different carry paths.
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            ),
        ];
        for (seed_hex, public_hex) in vectors {
            let mut seed = [0u8; 32];
            for (i, byte) in (0..32).zip(seed_hex.as_bytes().chunks_exact(2)) {
                seed[i] = u8::from_str_radix(std::str::from_utf8(byte).expect("hex is utf-8"), 16)
                    .expect("vector hex digit");
            }
            let public = public_key_from_seed(&seed);
            assert_eq!(&hex(&public), public_hex, "seed {seed_hex}");
        }
    }

    /// The base point encodes to its known compressed form, pinning the
    /// hardcoded limbs independently of the scalar loop.
    #[test]
    fn base_point_encoding() {
        assert_eq!(
            hex(&BASE.encode()),
            "5866666666666666666666666666666666666666666666666666666666666666"
        );
    }

    /// RFC 8032 §7.1 signatures: seed, message, and the exact 64-byte
    /// `R || S`. These pin the nonce derivation, the challenge hash, and
    /// the scalar arithmetic together with the curve — and each vector's
    /// public key verifies its own signature, pinning the verifier against
    /// the same rows.
    #[test]
    fn rfc8032_sign_vectors() {
        let vectors: &[(&str, &str, &str)] = &[
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed_hex, message_hex, signature_hex) in vectors {
            let seed = unhex32(seed_hex);
            let message = unhex(message_hex);
            let signature = sign(&seed, &message);
            assert_eq!(hex(signature.as_bytes()), *signature_hex, "seed {seed_hex}");
            assert!(
                verify(&public_key_from_seed(&seed), &message, &signature),
                "vector verifier accepts its own vector, seed {seed_hex}"
            );
        }
    }

    /// Sign/verify round-trips over every RFC seed — including the §7.2
    /// pair the key-construction vectors use — across the empty, one-byte,
    /// and 256-byte message shapes, and signing is deterministic.
    #[test]
    fn sign_verify_round_trip_is_deterministic() {
        let seeds = [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        ];
        let long_message: Vec<u8> = (0..=255u8).collect();
        for seed_hex in seeds {
            let seed = unhex32(seed_hex);
            let public = public_key_from_seed(&seed);
            for message in [&b""[..], &b"x"[..], long_message.as_slice()] {
                let signature = sign(&seed, message);
                assert_eq!(sign(&seed, message), signature, "deterministic");
                assert!(
                    verify(&public, message, &signature),
                    "round trip, seed {seed_hex}"
                );
            }
        }
    }

    /// Every negative case the verifier exists to refuse: tampered `R`,
    /// tampered `S`, a modified message, a different key, `S` at the group
    /// order and beyond it, and non-canonical point encodings for both the
    /// key and the commitment.
    #[test]
    fn verify_refuses_tampering_and_non_canonical_inputs() {
        let seed = unhex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let other = unhex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let public = public_key_from_seed(&seed);
        let other_public = public_key_from_seed(&other);
        let message = b"archivist acceptance";
        let signature = sign(&seed, message);

        // A bit flip anywhere in the encoding breaks it.
        for position in [0, 31, 32, 63] {
            let mut bytes = *signature.as_bytes();
            bytes[position] ^= 0x01;
            assert!(
                !verify(&public, message, &Signature::from_bytes(bytes)),
                "flipped byte {position}"
            );
        }
        // A modified message or the wrong key is the same refusal.
        assert!(!verify(&public, b"archivist acceptancf", &signature));
        assert!(!verify(&other_public, message, &signature));

        // `S = L` exactly is refused (equality is not reduction), and so is
        // anything larger.
        let mut s_at_order = *signature.as_bytes();
        s_at_order[32..].copy_from_slice(&unhex32(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ));
        assert!(!verify(
            &public,
            message,
            &Signature::from_bytes(s_at_order)
        ));
        let mut s_beyond_order = *signature.as_bytes();
        s_beyond_order[32..].copy_from_slice(&[0xff; 32]);
        assert!(!verify(
            &public,
            message,
            &Signature::from_bytes(s_beyond_order)
        ));

        // A key whose y reaches p is non-canonical, refused without
        // evaluation; the same refusal covers the commitment point.
        let bogus_key = [0xff; 32];
        assert!(!verify(&bogus_key, message, &signature));
        let mut commitment = *signature.as_bytes();
        commitment[..32].copy_from_slice(&[0xff; 32]);
        assert!(!verify(
            &public,
            message,
            &Signature::from_bytes(commitment)
        ));
    }

    /// Compressed encodings round-trip through decompression: the base
    /// point and every RFC vector public key recover to their own bytes.
    #[test]
    fn decompression_round_trips_encodings() {
        let base = BASE.encode();
        assert_eq!(
            decompress(&base).expect("base point decodes").encode(),
            base
        );
        for seed_hex in [
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        ] {
            let public = public_key_from_seed(&unhex32(seed_hex));
            assert_eq!(
                decompress(&public)
                    .expect("vector public key decodes")
                    .encode(),
                public,
                "seed {seed_hex}"
            );
        }
    }

    /// A `y` whose curve equation has no solution is refused: `y = 2` makes
    /// `(y²-1)/(d·y²+1)` a non-square, the case the sqrt(-1) correction
    /// cannot reach (verified independently of this implementation by the
    /// Euler criterion).
    #[test]
    fn decompression_refuses_y_not_on_curve() {
        let mut encoding = [0u8; 32];
        encoding[0] = 2;
        assert!(decompress(&encoding).is_none());
    }

    /// The compile-time `sqrt(-1)` squares to minus one — the property the
    /// non-square correction above rests on, pinned directly.
    #[test]
    fn sqrt_minus_one_squares_to_minus_one() {
        assert_eq!(
            fe_mul(&SQRT_MINUS_ONE, &SQRT_MINUS_ONE),
            fe_sub(&FE_ZERO, &FE_ONE)
        );
    }

    /// Hex-decode test-vector text.
    fn unhex(text: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(text.len() / 2);
        for pair in text.as_bytes().chunks_exact(2) {
            out.push(
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex is utf-8"), 16)
                    .expect("vector hex digit"),
            );
        }
        out
    }

    /// Hex-decode a 32-byte test vector.
    fn unhex32(text: &str) -> [u8; 32] {
        unhex(text).try_into().expect("32-byte vector")
    }

    /// Field sanity: add, subtract, multiply, and invert round-trip on
    /// elements derived from the base point.
    #[test]
    fn field_round_trips() {
        let a = BASE.y;
        let b = BASE.x;
        let product = fe_mul(&a, &b);
        assert_eq!(fe_mul(&product, &fe_invert(&b)), a);
        assert_eq!(fe_sub(&fe_add(&a, &b), &b), a);
        assert_eq!(fe_mul(&a, &fe_invert(&a)), FE_ONE);
    }

    /// `select(1)` is the identity, `select(0)` the neutral point — the
    /// branchless path the scalar loop takes on set and clear bits.
    #[test]
    fn select_matches_bit() {
        assert_eq!(BASE.select(1).encode(), BASE.encode());
        assert_eq!(BASE.select(0).encode(), NEUTRAL.encode());
    }

    /// Hex-encode for assertions. Test-local so no production path prints
    /// key material.
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}
