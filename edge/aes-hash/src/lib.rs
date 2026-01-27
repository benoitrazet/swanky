//! Correlation-robust hashing based on fixed-key AES.
//!
//! This crate provides objects that enable correlation-robust hashing based on
//! fixed-key AES. Such objects are useful for efficient OT extension and
//! circuit garbling, among other uses, and were introduced by Guo, Katz, Wang,
//! and Yu \[1\].
//!
//! A correlation-robust hash function $`H_{\mathsf{cr}}`$ is one that is
//! resistant to correlations in the hash input. That is, for a fixed $`R`$
//! (unknown to the adversary), an adversary cannot distinguish between
//! $`H_{\mathsf{cr}}(x \oplus R)`$ and a random function.
//!
//! A circular correlation-robust hash function $`H_{\mathsf{ccr}}`$ is similar,
//! with the addition of a "circularity" in the use of $`R`$. That is, for a
//! fixed $`R`$ (again unknown to the adversary), an adversary cannot
//! distinguish between $`H_{\mathsf{ccr}}(x \oplus R) \oplus b \cdot R`$ and a
//! random function, where $`b`$ is a bit controllable by the adversary.
//!
//! These two notions can be made _tweakable_ in that now the hash function
//! $`H`$ takes both input $`x`$ and a tweak $`t`$; otherwise, the security
//! notions are similar.
//!
//! In this crate we provide a correlation-robust hash function
//! [`CorrelationRobustHash`] (generally used for semi-honest protocols) and a
//! tweakable circular correlation-robust hash function
//! [`TweakableCircularCorrelationRobustHash`] (generally used for malicious
//! protocols).
//!
//! \[1\] C. Guo, J. Katz, X. Wang, Y. Yu. "Efficient and Secure Multiparty
//! Computation from Fixed-Key Block Ciphers." IEEE Security & Privacy. 2020.
#![deny(missing_docs)]

use std::sync::OnceLock;
use vectoreyes::{
    Aes128EncryptOnly, AesBlockCipher, U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

/// Correlation-robust hash function for 128-bit inputs.
///
/// For input $`x`$, the hash function computes $`\pi(x) \oplus x`$,
/// where $`\pi`$ is AES-128 encryption.
///
/// See <https://eprint.iacr.org/2019/074>, §7.2, for details.
#[derive(Clone, Debug)]
pub struct CorrelationRobustHash(Aes128EncryptOnly);

static CR_HASH_FIXED_KEY: OnceLock<CorrelationRobustHash> = OnceLock::new();
impl CorrelationRobustHash {
    /// Create a [`CorrelationRobustHash`] with a fixed key `b"Aes' 16 byte key"`.
    pub fn fixed_key() -> &'static Self {
        CR_HASH_FIXED_KEY
            .get_or_init(|| Self::new(const { U8x16::from_array(*b"Aes' 16 byte key") }))
    }

    /// Create a [`CorrelationRobustHash`] using the provided AES-128 key.
    pub fn new(key: U8x16) -> Self {
        Self(Aes128EncryptOnly::new_with_key(key))
    }

    /// Compute the hash function on the given input.
    #[inline]
    pub fn hash(&self, input: U8x16) -> U8x16 {
        self.0.encrypt(input) ^ input
    }

    /// Compute the hash function over a batch of inputs.
    pub fn hash_many<const N: usize>(&self, inputs: [U8x16; N]) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        let permutations = self.0.encrypt_many(inputs);
        permutations.array_zip(inputs).array_map(
            #[inline(always)]
            |(permutation, input)| permutation ^ input,
        )
    }
}

/// Tweakable circular correlation-robust hash function for 128-bit inputs.
///
/// For input $`x`$ and tweak $`t`$, the hash function computes $`\pi(\pi(x)
/// \oplus t) \oplus \pi(x)`$, where $`\pi`$ is AES-128 encryption.
///
/// See <https://eprint.iacr.org/2019/074>, §7.4, for details.
#[derive(Clone, Debug)]
pub struct TweakableCircularCorrelationRobustHash(Aes128EncryptOnly);

static TCCR_HASH_FIXED_KEY: OnceLock<TweakableCircularCorrelationRobustHash> = OnceLock::new();
impl TweakableCircularCorrelationRobustHash {
    /// A [`TweakableCircularCorrelationRobustHash`] with a fixed key `b"Aes' 16 byte key"`.
    pub fn fixed_key() -> &'static Self {
        TCCR_HASH_FIXED_KEY
            .get_or_init(|| Self::new(const { U8x16::from_array(*b"Aes' 16 byte key") }))
    }

    /// A [`TweakableCircularCorrelationRobustHash`] using the provided AES-128 key.
    pub fn new(key: U8x16) -> Self {
        Self(Aes128EncryptOnly::new_with_key(key))
    }

    /// Compute the hash function on the given input and tweak.
    pub fn hash(&self, input: U8x16, tweak: u128) -> U8x16 {
        let permutation = self.0.encrypt(input);
        let tweaked_permutation = self.0.encrypt(permutation ^ U8x16::from(tweak));
        permutation ^ tweaked_permutation
    }

    /// Compute the hash function over a batch of inputs using the same tweak.
    pub fn hash_many<const N: usize>(&self, inputs: [U8x16; N], tweak: u128) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        let permutations = self.0.encrypt_many(inputs);
        let tweaked_permutations = self.0.encrypt_many(permutations.array_map(
            #[inline(always)]
            |x| x ^ U8x16::from(tweak),
        ));
        permutations.array_zip(tweaked_permutations).array_map(
            #[inline(always)]
            |(a, b)| a ^ b,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{CorrelationRobustHash, TweakableCircularCorrelationRobustHash};
    use proptest::prelude::*;
    use vectoreyes::U8x16;

    proptest! {
        #[test]
        fn cr_hash_many_works(key in any::<u128>(), inputs in any::<[u128; 4]>()) {
            let cr_hash = CorrelationRobustHash::new(U8x16::from(key));
            let inputs = inputs.map(U8x16::from);
            let hashes = cr_hash.hash_many(inputs);
            for (input, hash) in inputs.into_iter().zip(hashes.into_iter()) {
                assert_eq!(hash, cr_hash.hash(input));
            }
        }
    }

    proptest! {
        #[test]
        fn tccr_hash_many_works(key in any::<u128>(), inputs in any::<[u128; 4]>(), tweak in any::<u128>()) {
            let tccr_hash = TweakableCircularCorrelationRobustHash::new(U8x16::from(key));
            let inputs = inputs.map(U8x16::from);
            let hashes = tccr_hash.hash_many(inputs, tweak);
            for (input, hash) in inputs.into_iter().zip(hashes.into_iter()) {
                assert_eq!(hash, tccr_hash.hash(input, tweak));
            }
        }
    }
}
