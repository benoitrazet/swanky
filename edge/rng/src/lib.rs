//! Random number generator based on fixed-key AES.
#![deny(missing_docs)]

use rand::{
    Rng, RngExt, SeedableRng, TryCryptoRng, TryRng,
    rand_core::{
        Infallible,
        block::{BlockRng, Generator},
    },
};
use vectoreyes::{
    Aes128EncryptOnly, AesBlockCipher, U8x16,
    array_utils::{ArrayUnrolledExt, ArrayUnrolledOps, UnrollableArraySize},
};

mod vectorized;
pub use vectorized::UniformIntegersUnderBound;

/// Random number generator based on fixed-key AES.
///
/// This uses AES in a counter-mode-esque way, but with the counter always
/// starting at zero. When used as a PRNG this is okay [TODO: citation?].
#[derive(Debug)]
pub struct SwankyRng(BlockRng<SwankyRngCore>);

impl TryRng for SwankyRng {
    type Error = Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.0.next_word())
    }
    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.0.next_u64_from_u32())
    }
    #[inline]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for SwankyRng {
    type Seed = <SwankyRngCore as SeedableRng>::Seed;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        SwankyRng(BlockRng::new(SwankyRngCore::from_seed(seed)))
    }
    #[inline]
    fn from_rng<R: Rng + ?Sized>(rng: &mut R) -> Self {
        SwankyRng(BlockRng::new(SwankyRngCore::from_rng(rng)))
    }
}

impl TryCryptoRng for SwankyRng {}

impl SwankyRng {
    /// Create a new random number generator using a random seed from
    /// `rand::random`.
    #[inline]
    pub fn new() -> Self {
        let seed: U8x16 = rand::random();
        SwankyRng::from_seed(seed)
    }

    /// Create a new random number generator using a given seed and IV.
    pub fn from_seed_and_iv(seed: U8x16, iv: u128) -> Self {
        Self(BlockRng::new(SwankyRngCore::from_seed_and_iv(seed, iv)))
    }

    /// Create a new RNG using a random seed from this one.
    #[inline]
    pub fn fork(&mut self) -> Self {
        let seed = self.random::<U8x16>();
        SwankyRng::from_seed(seed)
    }

    /// Generate random bits.
    #[inline(always)]
    pub fn random_bits(&mut self) -> [U8x16; Aes128EncryptOnly::BLOCK_COUNT_HINT] {
        self.0.core.gen_rand_bits()
    }

    /// Generate `N * 128` random bits.
    ///
    /// # Alternatives
    /// Consider using [Self::random_bits] instead.
    #[inline(always)]
    pub fn random_bits_custom_size<const N: usize>(&mut self) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        self.0.core.gen_rand_bits()
    }
}

impl Default for SwankyRng {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// The core of [`SwankyRng`], used with `BlockRng`.
#[derive(Debug)]
pub struct SwankyRngCore {
    aes: Aes128EncryptOnly,
    counter: u128,
}

impl SwankyRngCore {
    fn from_seed_and_iv(seed: U8x16, iv: u128) -> Self {
        let mut rng = Self::from_seed(seed);
        rng.counter = iv;
        rng
    }

    #[inline(always)]
    fn gen_rand_bits<const N: usize>(&mut self) -> [U8x16; N]
    where
        ArrayUnrolledOps: UnrollableArraySize<N>,
    {
        let blocks = <[U8x16; N]>::array_generate(
            #[inline(always)]
            |_| {
                self.counter += 1;
                self.counter.into()
            },
        );
        self.aes.encrypt_many(blocks)
    }
}

impl Generator for SwankyRngCore {
    type Output = [u32; Aes128EncryptOnly::BLOCK_COUNT_HINT * 4];

    // Compute `E(state)` eight times, where `state` is a counter.
    #[inline]
    fn generate(&mut self, results: &mut Self::Output) {
        *results = bytemuck::cast(self.gen_rand_bits::<{ Aes128EncryptOnly::BLOCK_COUNT_HINT }>());
    }
}

impl SeedableRng for SwankyRngCore {
    type Seed = U8x16;

    #[inline]
    fn from_seed(seed: Self::Seed) -> Self {
        SwankyRngCore {
            aes: Aes128EncryptOnly::new_with_key(seed),
            counter: 0,
        }
    }
}

impl From<SwankyRngCore> for SwankyRng {
    #[inline]
    fn from(core: SwankyRngCore) -> Self {
        SwankyRng(BlockRng::new(core))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;

    #[test]
    fn test_generate() {
        let mut rng = SwankyRng::new();
        let a = rng.random::<[U8x16; 8]>();
        let b = rng.random::<[U8x16; 8]>();
        assert_ne!(a, b);
    }
}
