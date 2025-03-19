/*!
Implementation of algorithms related to consistency checks.
 *
*/
#![allow(clippy::needless_range_loop)]
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM};
use crate::vole::commit_reconstruct::B;
use crate::vole::crypto_primitives::CHALL1_LENGTH;
use generic_array::sequence::Concat;
use generic_array::{
    sequence::Split,
    typenum::{U16, U32, U48, U64, U80, U96},
    GenericArray,
};
use itertools::izip;
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::{F128b, F8b, F2};
use swanky_serialization::CanonicalSerialize;

/// Packs bits of the input into `F128b`s. This does not do a field-to-field transformation;
/// it uses `F128b` as a representation of 128 bits, not as a polynomial!
fn pack_f128b(arrs: &[[F8b; REPETITION_PARAM]]) -> Vec<F128b> {
    arrs.iter()
        .map(|xi| {
            let xi_bytes = xi.map(|xij| xij.to_bytes()[0]);
            F128b::from_bytes(&xi_bytes.into())
        })
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Take a sequence of boolean field values and pack them into `F128b` values. It padds the last values in the sequence if necessary.
///
/// This implements a specialization of ToField Fig 3.1 in FAEST spec
#[inline(never)]
fn to_field_f128_and_pad<I: Iterator<Item = F2>>(x: I, x_len: usize) -> Vec<F128b> {
    let floor = x_len / 128;
    let how_many = floor + if (x_len - (floor) * 128) != 0 { 1 } else { 0 };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [0u8; 128 / 8];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.into_iter() {
        b_128[byte_num] |= if b == F2::ZERO { 0 } else { 1 << bit_num };
        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (128 / 8) - 1 {
                out.push(F128b::from_bytes(&b_128.into()).unwrap());

                // reset
                byte_num = 0;
                // reset
                b_128 = [0u8; 128 / 8];
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
    if (bit_num != 0) | (byte_num != 0) {
        out.push(F128b::from_bytes(&b_128.into()).unwrap())
    }

    assert_eq!(out.len(), how_many);
    out
}

/// Take a sequence of [`F128b`] values, interpret every value into its bit decomposition,
/// that becomes a n*128 boolean matrix where n is the length of the sequence.
/// Apply `to_field_f128_and_pad` to every column in lock step and emit a sequence of
/// 128 [`F128b`] values.
#[inline(never)]
fn to_field_f128_and_pad_lockstep(x: &[F128b]) -> Vec<[F128b; SECURITY_PARAM]> {
    let floor = x.len() / 128;
    let how_many = floor + if (x.len() - (floor) * 128) != 0 { 1 } else { 0 };
    let mut out = Vec::with_capacity(how_many);

    let mut b_128 = [[0u8; 128 / 8]; 128];
    let mut byte_num = 0;
    let mut bit_num: usize = 0;
    for b in x.iter() {
        let bs = b.bit_decomposition();
        for (i, b) in bs.iter().enumerate() {
            b_128[i][byte_num] |= if !*b { 0 } else { 1 << bit_num };
        }
        if bit_num == 7 {
            bit_num = 0; // restart at the beginning of byte
            if byte_num == (128 / 8) - 1 {
                let arr: [F128b; SECURITY_PARAM] =
                    b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
                out.push(arr);

                // reset
                byte_num = 0;
                // reset
                b_128 = [[0u8; 128 / 8]; 128];
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }

    // Still have to push a last value if the previous loop terminated before processing `SECURITY_PARAMETER` bits.
    if (bit_num != 0) | (byte_num != 0) {
        let arr: [F128b; SECURITY_PARAM] = b_128.map(|v| F128b::from_bytes(&v.into()).unwrap());
        out.push(arr);
    }

    assert_eq!(out.len(), how_many);
    out
}

/// Hash as produced by [`vole_hash`].
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct HashConsistency([F2; SECURITY_PARAM + B]);

impl Default for HashConsistency {
    fn default() -> Self {
        Self([Default::default(); SECURITY_PARAM + B])
    }
}

impl IntoIterator for &HashConsistency {
    type Item = F2;
    type IntoIter = <[F2; SECURITY_PARAM + B] as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl HashConsistency {
    pub(crate) fn len(&self) -> usize {
        SECURITY_PARAM + B
    }

    /// Convert a consistency hash to a vector of bytes
    ///
    /// packing the `F2` values in `u8`.
    #[cfg(test)]
    pub(crate) fn pack_to_bytes(&self) -> Vec<u8> {
        let mut out = vec![];
        for chunk in self.0.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b == F2::ONE {
                    byte |= 1 << i;
                }
            }
            out.push(byte);
        }
        out
    }

    /// Convert a [`HashConsistency`] to a list of bytes, without packing.
    pub(crate) fn as_bytes(&self) -> [u8; SECURITY_PARAM + B] {
        self.0.map(|f2| f2.to_bytes()[0])
    }
}

/// Precomputation for the VOLE-Hash.
///
/// Drawn from FAEST spec v1.1, Fig 4.4, with some modifications (noted inline).
pub(crate) struct VoleHasher {
    r0: F128b,
    r1: F128b,
    r2: F128b,
    r3: F128b,
    s0_powers: Vec<F128b>,
    s1_powers: Vec<F128b>,
}

impl VoleHasher {
    pub(crate) fn from_seed(seed: [u8; CHALL1_LENGTH], ell: usize) -> Self {
        // Line 2.
        let seed_ga: GenericArray<u8, U96> = GenericArray::from(seed);
        let (r0_bytes, rest): (GenericArray<u8, U16>, GenericArray<u8, U80>) = seed_ga.split();
        let (r1_bytes, rest): (GenericArray<u8, U16>, GenericArray<u8, U64>) = rest.split();
        let (r2_bytes, rest): (GenericArray<u8, U16>, GenericArray<u8, U48>) = rest.split();
        let (r3_bytes, rest): (GenericArray<u8, U16>, GenericArray<u8, U32>) = rest.split();
        // Note: In the spec, `t` is 64 bits; here it's called `s1` and has 128 bits.
        let (s_bytes, t_bytes): (GenericArray<u8, U16>, GenericArray<u8, U16>) = rest.split();

        // Lines 3 - 5.
        let r0 = F128b::from_bytes(&r0_bytes).unwrap();
        let r1 = F128b::from_bytes(&r1_bytes).unwrap();
        let r2 = F128b::from_bytes(&r2_bytes).unwrap();
        let r3 = F128b::from_bytes(&r3_bytes).unwrap();
        // Note: These are called `s` and `t` in the spec.
        let s0 = F128b::from_bytes(&s_bytes).unwrap();
        let s1 = F128b::from_bytes(&t_bytes).unwrap();

        // Line 6.
        let ell_prime = SECURITY_PARAM * (ell + SECURITY_PARAM).div_ceil(SECURITY_PARAM);

        // Precomputation: This is part of Line 10.
        // This differs from the FAEST spec where the powers are in reverse order; this is also valid!
        let mut s0_powers = Vec::with_capacity(ell_prime / SECURITY_PARAM - 1);
        s0_powers.push(s0);
        for i in 1..ell_prime / SECURITY_PARAM - 1 {
            s0_powers.push(s0_powers[i - 1] * s0);
        }

        // Precomputation: This is part of Line 11.
        // This differs from the FAEST spec where the powers are in reverse order; this is also valid!
        // This differs from the FAEST spec because it uses a different field.
        let mut s1_powers = Vec::with_capacity((ell_prime / 64) - 1);
        s1_powers.push(s1);
        for i in 1..ell_prime / 64 - 1 {
            s1_powers.push(s1_powers[i - 1] * s1);
        }

        Self {
            r0,
            r1,
            r2,
            r3,

            s0_powers,
            s1_powers,
        }
    }
}

/// Function doing linear hashing of vector of boolean field elements.
#[inline(never)]
pub(crate) fn vole_hash<I1: Iterator<Item = F2>, I2: Iterator<Item = F2>>(
    seed: &[u8],
    x0: I1,
    x0_len: usize,
    x1: I2,
    x1_len: usize,
) -> HashConsistency {
    let hasher = VoleHasher::from_seed(seed.try_into().unwrap(), x0_len - SECURITY_PARAM);

    assert_eq!(x1_len, SECURITY_PARAM + B);

    // Line 7.
    let x0_vec = to_field_f128_and_pad(x0, x0_len);

    // Lines 10 - 11.
    let mut h0 = F128b::ZERO;
    let mut h1 = F128b::ZERO;
    for (x0_i, s0_i, s1_i) in izip!(x0_vec, hasher.s0_powers, hasher.s1_powers) {
        h0 += s0_i * x0_i;
        h1 += s1_i * x0_i;
    }

    // Line 13.
    let h2 = hasher.r0 * h0 + hasher.r1 * h1;
    let h3 = hasher.r2 * h0 + hasher.r3 * h1;

    // Line 14 (call ToBits and truncate).
    let h2_bits = h2.bit_decomposition();
    let (h3_bits, _unused): (GenericArray<bool, U16>, _) = h3.bit_decomposition().split();

    // Line 14 (append).
    let all_bits: [bool; SECURITY_PARAM + B] = h2_bits.concat(h3_bits).into();

    // Line 14 (XOR with x1). This unwrap is safe because the two inputs must be the expected length.
    let out: [F2; SECURITY_PARAM + B] = izip!(all_bits, x1)
        .map(|(b1, b2)| (F2::from(b1) + b2))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap() ;

    HashConsistency(out)
}

/// Function doing linear hashing of the column of bits in lock-step.
///
/// There are `REPETITION_PARAM` tracks where one group of bits is provided as a [`F128b`] value.
#[inline(never)]
pub(crate) fn vole_hash_lockstep(
    seed: &[u8],
    x0: &[[F8b; REPETITION_PARAM]],
    x1: &[[F8b; REPETITION_PARAM]],
) -> [HashConsistency; SECURITY_PARAM] {
    assert_eq!(x1.len(), SECURITY_PARAM + B);

    let hasher = VoleHasher::from_seed(seed.try_into().unwrap(), x0.len() - SECURITY_PARAM);

    // NOTE (optimize): This packed `f128b` of `x0` is a convenient holder for bits, and should
    // not be treated like a field element.
    let x0_vec = to_field_f128_and_pad_lockstep(&pack_f128b(x0));

    let mut h0 = [F128b::ZERO; SECURITY_PARAM];
    let mut h1 = [F128b::ZERO; SECURITY_PARAM];
    for (x0_i, s0_i, s1_i) in izip!(x0_vec, hasher.s0_powers, hasher.s1_powers) {
        for j in 0..SECURITY_PARAM {
            // This loop is the parallel part
            h0[j] += s0_i * x0_i[j];
            h1[j] += s1_i * x0_i[j];
        }
    }
    let mut h2 = [F128b::ZERO; SECURITY_PARAM];
    let mut h3 = [F128b::ZERO; SECURITY_PARAM];
    for j in 0..SECURITY_PARAM {
        h2[j] = hasher.r0 * h0[j] + hasher.r1 * h1[j];
        h3[j] = hasher.r2 * h0[j] + hasher.r3 * h1[j];
    }

    let mut out = [HashConsistency::default(); SECURITY_PARAM];

    let x1_packed = pack_f128b(x1);

    for j in 0..SECURITY_PARAM {
        // Line 14 (call ToBits and truncate).
        let h2_bits = h2[j].bit_decomposition();
        let (h3_bits, _unused): (GenericArray<bool, U16>, _) = h3[j].bit_decomposition().split();

        // Line 14 (append).
        let all_bits: [bool; SECURITY_PARAM + B] = h2_bits.concat(h3_bits).into();

        let mut x1_bits = [false; SECURITY_PARAM + B];
        for col in 0..SECURITY_PARAM + B {
            x1_bits[col] = x1_packed[col].bit_decomposition()[j];
        }

        // Line 14 (XOR with x1).
        let single_out = izip!(all_bits, x1_bits)
                .map(|(b1, b2)| F2::from(b1) + F2::from(b2))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
        out[j] = HashConsistency(single_out);
    }
    out
}

#[cfg(test)]
mod test {
    use super::{to_field_f128_and_pad, vole_hash};
    use crate::parameters::SECURITY_PARAM;
    use crate::vole::commit_reconstruct::B;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F128b;
    use swanky_field_binary::F2;
    use swanky_serialization::CanonicalSerialize;

    #[test]
    fn test_padding_of_to_field_f128_and_pad() {
        let v = vec![F2::ZERO; 1000];
        let t = to_field_f128_and_pad(v.into_iter(), 1000);
        assert_eq!(t.len(), 1000 / 128 + 1);

        let v = vec![F2::ZERO; 128];
        let t = to_field_f128_and_pad(v.into_iter(), 128);
        assert_eq!(t.len(), 1);

        let v = vec![F2::ZERO; 129];
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        assert_eq!(t.len(), 2);

        let mut v = vec![F2::ZERO; 130];
        v[0] = F2::ONE;
        v[129] = F2::ONE;
        let t = to_field_f128_and_pad(v.into_iter(), 129);
        let mut res1 = [0u8; 16];
        res1[0] = 1u8;
        assert_eq!(t[0], F128b::from_bytes(&res1.into()).unwrap());
        let mut res2 = [0u8; 16];
        res2[0] = 2u8;
        assert_eq!(t[1], F128b::from_bytes(&res2.into()).unwrap());
        // TODO: Could generate random values and decompose the generated F128b and check the equivalence
    }

    // Test that [`vole_hash`] returns 0 when all the inputs are 0.
    #[test]
    fn test_vole_hash_zero() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let x1 = [F2::ZERO; SECURITY_PARAM + B];
        let v = vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for b in v.0.iter() {
            assert_eq!(*b, F2::ZERO);
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_last_xor() {
        let seeds = [0u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        let x0 = [F2::ZERO; HOW_MANY + SECURITY_PARAM];
        let mut x1 = [F2::ZERO; SECURITY_PARAM + B];
        let pos = 13;
        x1[pos] = F2::ONE;
        let v = vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for (i, b) in v.0.iter().enumerate() {
            if i == pos {
                assert_eq!(*b, F2::ONE);
            } else {
                assert_eq!(*b, F2::ZERO);
            }
        }
    }

    // Test the xor part at the end of [`vole_hash`]
    #[test]
    fn test_vole_hash_is_linear() {
        let seeds = [1u8; (SECURITY_PARAM * 6) / 8];

        const HOW_MANY: usize = 1000;
        const BOUND: usize = HOW_MANY + SECURITY_PARAM;
        const LAST: usize = SECURITY_PARAM + B;
        let x0 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x1 = [F2::ZERO; HOW_MANY + 2 * SECURITY_PARAM + B];
        let x2 = [F2::ONE; HOW_MANY + 2 * SECURITY_PARAM + B];

        let v0 = vole_hash(
            &seeds,
            x0.into_iter().take(BOUND),
            BOUND,
            x0.into_iter().skip(BOUND),
            LAST,
        );
        let v1 = vole_hash(
            &seeds,
            x1.into_iter().take(BOUND),
            BOUND,
            x1.into_iter().skip(BOUND),
            LAST,
        );
        let v2 = vole_hash(
            &seeds,
            x2.into_iter().take(BOUND),
            BOUND,
            x2.into_iter().skip(BOUND),
            LAST,
        );
        for ((a, b), c) in v0.0.iter().zip(v1.0.iter()).zip(v2.0.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }
}
