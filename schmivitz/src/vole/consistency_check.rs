/*!
Implementation of algorithms related to consistency checks.
 *
*/
#![allow(clippy::needless_range_loop)]
use crate::parameters::REPETITION_PARAM;
use crate::parameters::SECURITY_PARAM;
use crate::vole::commit_reconstruct::B;
use crate::vole::crypto_primitives::CHALL1_LENGTH;
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
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

/// Function doing linear hashing of vector of boolean field elements.
#[inline(never)]
pub(crate) fn vole_hash<I1: Iterator<Item = F2>, I2: Iterator<Item = F2>>(
    seed: &[u8],
    x0: I1,
    x0_len: usize,
    x1: I2,
    x1_len: usize,
) -> HashConsistency {
    assert_eq!(seed.len(), CHALL1_LENGTH);
    assert_eq!(x1_len, SECURITY_PARAM + B);

    let byte_len: usize = 128 / 8;
    let mut tmp = [u8::default(); 128 / 8];
    tmp.copy_from_slice(&seed[0..byte_len]);
    let r0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len..byte_len * 2]);
    let r1 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 2..byte_len * 3]);
    let r2 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 3..byte_len * 4]);
    let r3 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 4..byte_len * 5]);
    let s0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 5..byte_len * 6]);
    let s1 = F128b::from_bytes(&tmp.into()).unwrap();

    let floor = x0_len / SECURITY_PARAM;
    let how_many = floor
        + if (x0_len - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    let x0_vec = to_field_f128_and_pad(x0, x0_len);
    // NOTE: we dont need to compute how_many, we could directly use `x0_vec.len()`.
    assert_eq!(x0_vec.len(), how_many);

    let mut h0 = F128b::ZERO;
    let mut h1 = F128b::ZERO;
    let mut s0_power = s0;
    let mut s1_power = s1;
    for i in 0..how_many {
        h0 += s0_power * x0_vec[i];
        h1 += s1_power * x0_vec[i];
        // NOTE: difference from FAEST spec where the powers are in
        // reverse order, this is also valid.
        s0_power *= s0;
        s1_power *= s1;
    }
    let h2 = r0 * h0 + r1 * h1;
    let h3 = r2 * h0 + r3 * h1;

    let h2_bits = h2.bit_decomposition();
    let h3_bits = h3.bit_decomposition();

    let mut all_bits = Vec::with_capacity(SECURITY_PARAM + B);
    all_bits.extend_from_slice(h2_bits.as_slice());
    all_bits.extend_from_slice(h3_bits.as_slice());

    all_bits.truncate(x1_len);
    assert_eq!(all_bits.len(), SECURITY_PARAM + B);

    let mut out = [F2::ZERO; SECURITY_PARAM + B];

    out.copy_from_slice(
        all_bits
            .iter()
            .zip(x1)
            .map(|(b1, b2)| (F2::from(*b1) + b2))
            .collect::<Vec<_>>()
            .as_slice(),
    );
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
    assert_eq!(seed.len(), CHALL1_LENGTH);
    assert_eq!(x1.len(), SECURITY_PARAM + B);
    let byte_len: usize = 128 / 8;
    let mut tmp = [u8::default(); 128 / 8];

    // `r0`,`r1`, `r2`, `r3`, `s0` and `s1` are the same values of every track.
    tmp.copy_from_slice(&seed[0..byte_len]);
    let r0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len..byte_len * 2]);
    let r1 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 2..byte_len * 3]);
    let r2 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 3..byte_len * 4]);
    let r3 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 4..byte_len * 5]);
    let s0 = F128b::from_bytes(&tmp.into()).unwrap();
    tmp.copy_from_slice(&seed[byte_len * 5..byte_len * 6]);
    let s1 = F128b::from_bytes(&tmp.into()).unwrap();

    let floor = x0.len() / SECURITY_PARAM;
    let how_many = floor
        + if (x0.len() - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    let x0_vec = to_field_f128_and_pad_lockstep(&pack_f128b(x0));
    // NOTE: we dont need to compute how_many, we could directly use `x0_vec.len()`.
    assert_eq!(x0_vec.len(), how_many);

    let mut h0 = [F128b::ZERO; SECURITY_PARAM];
    let mut h1 = [F128b::ZERO; SECURITY_PARAM];
    let mut s0_power = s0;
    let mut s1_power = s1;
    for i in 0..how_many {
        // This is where performing in lockstep is beneficial, saving on
        // computing `s0_power`/`s1_power` only once for every row.
        for j in 0..SECURITY_PARAM {
            // This loop is the parallel part
            h0[j] += s0_power * x0_vec[i][j];
            h1[j] += s1_power * x0_vec[i][j];
        }
        // NOTE: difference from FAEST spec where the powers are in
        // reverse order, this is also valid.
        s0_power *= s0;
        s1_power *= s1;
    }
    let mut h2 = [F128b::ZERO; SECURITY_PARAM];
    let mut h3 = [F128b::ZERO; SECURITY_PARAM];
    for j in 0..SECURITY_PARAM {
        h2[j] = r0 * h0[j] + r1 * h1[j];
        h3[j] = r2 * h0[j] + r3 * h1[j];
    }

    let mut out = [HashConsistency::default(); SECURITY_PARAM];

    let x1_packed = pack_f128b(x1);

    for j in 0..SECURITY_PARAM {
        let h2_bits = h2[j].bit_decomposition();
        let h3_bits = h3[j].bit_decomposition();

        let mut all_bits = Vec::with_capacity(SECURITY_PARAM + B);
        all_bits.extend_from_slice(h2_bits.as_slice());
        all_bits.extend_from_slice(h3_bits.as_slice());

        all_bits.truncate(x1.len());
        assert_eq!(all_bits.len(), SECURITY_PARAM + B);

        let mut single_out = [F2::ZERO; SECURITY_PARAM + B];

        let mut x1_bits = [false; SECURITY_PARAM + B];
        for col in 0..SECURITY_PARAM + B {
            x1_bits[col] = x1_packed[col].bit_decomposition()[j];
        }
        single_out.copy_from_slice(
            all_bits
                .iter()
                .zip(x1_bits)
                .map(|(b1, b2)| F2::from(*b1) + F2::from(b2))
                .collect::<Vec<_>>()
                .as_slice(),
        );
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
