//! Utility functions for working with [`NeuralNet`](crate::NeuralNet)s.

use fancy_garbling::util as numbers;

/// Convert a list of bitwidths to their associated moduli.
pub fn bitwidths_to_moduli(bitwidths: &[usize]) -> Vec<u128> {
    bitwidths
        .iter()
        .map(|&b| fancy_garbling::util::modulus_with_width(b as u32))
        .collect()
}

/// The index of the max value in `xs`.
pub fn index_of_max(xs: &[i64]) -> usize {
    let mut max_val = i64::MIN;
    let mut max_ix = 0;
    for (i, &x) in xs.iter().enumerate() {
        if x > max_val {
            max_ix = i;
            max_val = x;
        }
    }
    max_ix
}

/// The value `x % q`.
///
/// # Panics
/// Panics if the value `x` is too large/small for `q`.
pub fn to_mod_q(x: i64, q: u128) -> u128 {
    assert!(
        ((x as i128) >= 0 && (x as i128) < q as i128 / 2)
            || ((x as i128) < 0 && (x as i128) >= -(q as i128 / 2)),
        "x={x} is too large/small for q={q}",
    );
    ((q as i128 + x as i128) % q as i128) as u128
}

/// The value `x % q` as a `i64`.
pub fn from_mod_q(x: u128, q: u128) -> i64 {
    if x >= q / 2 {
        (x as i128 - q as i128) as i64
    } else {
        x as i64
    }
}

/// The value `x % q` in CRT form.
///
/// # Panics
/// Panics if the value `x` is too large/small for `q`.
pub fn to_mod_q_crt(x: i64, q: u128) -> Vec<u16> {
    numbers::crt_factor(to_mod_q(x, q), q)
}

/// The value `x % q` as a `i64`, where `x` is provided in CRT form.
pub fn from_mod_q_crt(xs: &[u16], q: u128) -> i64 {
    from_mod_q(numbers::crt_inv_factor(xs, q), q)
}

/// Negate `x` using two's complement.
pub fn twos_complement_negate(x: u128, nbits: usize) -> u128 {
    let mask = (1 << nbits) - 1;
    ((!x) & mask) + 1
}

/// Convert an `i64` to a `u128`, where negative values are converted using
/// two's complement.
pub fn i64_to_twos_complement(x: i64, nbits: usize) -> u128 {
    if x >= 0 {
        x as u128
    } else {
        twos_complement_negate((-x) as u128, nbits)
    }
}

/// Covert a `u128` to a `i64`, where negative values are converted using two's
/// complement.
pub fn i64_from_twos_complement(x: u128, nbits: usize) -> i64 {
    if x >= 1 << (nbits - 1) {
        -(twos_complement_negate(x, nbits) as i64)
    } else {
        x as i64
    }
}

/// Convert a sequence of bits into its `i64` representation.
pub fn i64_from_bits(bits: &[u16]) -> i64 {
    let x = numbers::u128_from_bits(bits);
    i64_from_twos_complement(x, bits.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, thread_rng};

    #[test]
    fn convert_crt() {
        let mut rng = thread_rng();
        for _ in 0..1024 {
            let nprimes = 2_usize + (rng.r#gen::<usize>() % 16);
            let q = numbers::modulus_with_nprimes(nprimes);
            let x = rng.r#gen::<i64>() % (q / 2) as i64;
            assert_eq!(x, from_mod_q_crt(&to_mod_q_crt(x, q), q));
        }
    }

    #[test]
    fn convert_binary() {
        let mut rng = thread_rng();
        let nbits = 2 + rng.r#gen::<usize>() % 120;
        for _ in 0..128 {
            let x = rng.r#gen::<i64>() % nbits as i64;
            assert_eq!(
                x,
                i64_from_twos_complement(i64_to_twos_complement(x, nbits), nbits)
            );
        }
    }
}
