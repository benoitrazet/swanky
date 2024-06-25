/*! */
#![allow(clippy::needless_range_loop)]
use crate::parameters::SECURITY_PARAM;
use crate::vole::crypto_primitives::CHALL1_LENGTH;
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::F128b;
use swanky_field_binary::F8b;
use swanky_field_binary::F2;
use swanky_serialization::CanonicalSerialize;

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
                byte_num = 0;
                b_128 = [0u8; 128 / 8]; // reset
            } else {
                byte_num += 1;
            }
        } else {
            bit_num += 1;
        }
    }
    if (bit_num != 0) | (byte_num != 0) {
        out.push(F128b::from_bytes(&b_128.into()).unwrap())
    }

    assert_eq!(out.len(), how_many);
    out
}

/// TODO
#[inline(never)]
pub fn simply_vole_hash<I1: Iterator<Item = F2>, I2: Iterator<Item = F2>>(
    seed: &[u8],
    x0: I1,
    x0_len: usize,
    x1: I2,
    x1_len: usize,
) -> Vec<F2> {
    assert_eq!(seed.len(), CHALL1_LENGTH);
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

    // TODO: we dont need to compute how_many, we could directly use `x0_vec.len()`
    let floor = x0_len / SECURITY_PARAM;
    let how_many = floor
        + if (x0_len - floor * SECURITY_PARAM) != 0 {
            1
        } else {
            0
        };

    let x0_vec = to_field_f128_and_pad(x0, x0_len);
    assert_eq!(x0_vec.len(), how_many);
    let mut h0 = F128b::ZERO;
    let mut h1 = F128b::ZERO;
    let mut s0_power = s0;
    let mut s1_power = s1;
    for i in 0..how_many {
        h0 += s0_power * x0_vec[i];
        h1 += s1_power * x0_vec[i];
        s0_power *= s0; // TODO: should I do the power in reverse order?? as in the spec.
                        // The answer was that it does not matter.
        s1_power *= s1;
    }
    let h2 = r0 * h0 + r1 * h1;
    let h3 = r2 * h0 + r3 * h1;

    let h2_bits = h2.bit_decomposition();
    let h3_bits = h3.bit_decomposition();

    let mut all_bits = vec![];
    all_bits.extend_from_slice(h2_bits.as_slice());
    all_bits.extend_from_slice(h3_bits.as_slice());

    all_bits.truncate(x1_len);
    all_bits
        .iter()
        .zip(x1)
        .map(|(b1, b2)| (if *b1 { F2::ONE } else { F2::ZERO }) + b2)
        .collect()
}

/// TODO
pub struct BitDecomposer<'a> {
    data: &'a Vec<Vec<F8b>>,
    outer_index: usize,
    inner_index: usize,
    bit_index: u8,
}

impl<'a> BitDecomposer<'a> {
    fn new(data: &'a Vec<Vec<F8b>>) -> Self {
        Self {
            data,
            outer_index: 0,
            inner_index: 0,
            bit_index: 0,
        }
    }

    fn next_position(&mut self) {
        if self.inner_index == self.data[0].len() - 1 {
            self.inner_index = 0;
            if self.bit_index == 7 {
                self.bit_index = 0;
                self.outer_index += 1;
            } else {
                self.bit_index += 1;
            }
        } else {
            self.inner_index += 1;
        }
    }

    fn is_out_of_range(&self) -> bool {
        self.outer_index >= self.data.len()
    }
}

impl<'a> Iterator for BitDecomposer<'a> {
    type Item = F2;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_out_of_range() {
            return None;
        }

        let b = if self.data[self.outer_index][self.inner_index].get_bit(self.bit_index) == 1u8 {
            F2::ONE
        } else {
            F2::ZERO
        };
        self.next_position();
        Some(b)
    }
}

/// TODO
pub fn decompose_bits(data: &Vec<Vec<F8b>>) -> BitDecomposer<'_> {
    BitDecomposer::new(data)
}

#[cfg(test)]
mod test {
    use super::{decompose_bits, simply_vole_hash, to_field_f128_and_pad};
    use crate::parameters::SECURITY_PARAM;
    use crate::vole::commit_reconstruct::B;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;
    use swanky_field_binary::{F128b, F8b};
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
        let v = simply_vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for b in v.iter() {
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
        let v = simply_vole_hash(
            &seeds,
            x0.into_iter(),
            HOW_MANY + SECURITY_PARAM,
            x1.into_iter(),
            SECURITY_PARAM + B,
        );
        for (i, b) in v.iter().enumerate() {
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

        let v0 = simply_vole_hash(
            &seeds,
            x0.clone().into_iter().take(BOUND),
            BOUND,
            x0.clone().into_iter().skip(BOUND),
            LAST,
        );
        let v1 = simply_vole_hash(
            &seeds,
            x1.clone().into_iter().take(BOUND),
            BOUND,
            x1.clone().into_iter().skip(BOUND),
            LAST,
        );
        let v2 = simply_vole_hash(
            &seeds,
            x2.clone().into_iter().take(BOUND),
            BOUND,
            x2.clone().into_iter().skip(BOUND),
            LAST,
        );
        for ((a, b), c) in v0.iter().zip(v1.iter()).zip(v2.iter()) {
            assert_eq!(*a + *b, *c);
        }
    }

    #[test]
    fn test_bit_decomposer() {
        let v: Vec<Vec<F8b>> = vec![vec![2u8.into(), 128u8.into()], vec![0u8.into(), 5.into()]];
        let indices = [2, 2 * 8 - 1, 2 * 8 + 1, 2 * 8 + 5];

        for (i, b) in decompose_bits(&v).into_iter().enumerate() {
            if i == indices[0] || i == indices[1] || i == indices[2] || i == indices[3] {
                assert_eq!(b, F2::ONE);
            } else {
                assert_eq!(b, F2::ZERO);
            }
        }
    }
}
