//! Two-party functionality $`\mathcal{F}_{\mathsf{Rand}}`$ for generating
//! unbiased random values.
//!
//! This crate implements a two-party instantiation of the
//! $`\mathcal{F}_{\mathsf{Rand}}`$ functionality as defined below:
//!
//! 1. Upon receiving $`(\mathsf{Rand}, \mathcal{S})`$ from all parties, where
//!    $`\mathcal{S}`$ is some finite set with an efficient sampling algorithm,
//!    output $`r \from_\$ \mathcal{S}`$.
//!
//! There are two instantiations of this functionality. [`random`] allows the
//! generation of a random value of any type `T` that implements
//! [`Distribution`]. [`random_seed`] allows the generation of values of type
//! [`U8x16`], which is more efficient than using [`random`] for `T = U8x16`.
//!
//! # Security
//!
//! The implementation is secure in the random oracle model under the assumption
//! that [Blake3](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE3) is
//! indistinguishable from a random oracle.
//!
//! # Round Complexity
//!
//! The protocol requires 1.5 rounds of communication.
#![deny(missing_docs)]

use rand::{CryptoRng, Rng, SeedableRng, distributions::Standard, prelude::Distribution};
use swanky_aes_rng::AesRng;
use swanky_channel::Channel;
use swanky_party::Party;
use swanky_serialization::CanonicalSerialize;
use vectoreyes::U8x16;

/// Generate a random value of type `T`.
pub fn random<P: Party, T, RNG: CryptoRng + Rng>(
    channel: &mut Channel,
    rng: &mut RNG,
) -> eyre::Result<T>
where
    Standard: Distribution<T>,
{
    // The protocol works as follows:
    //
    // 1. Run `random_seed` to generate a random seed.
    // 2. Use this to seed a RNG which we then use to generate a random `T`.
    let seed = random_seed::<P, _>(channel, rng)?;
    let mut rng_new = AesRng::from_seed(seed);
    Ok(rng_new.r#gen::<T>())
}

/// Generate a random seed (that is, a 128-bit value).
pub fn random_seed<P: Party, RNG: CryptoRng + Rng>(
    channel: &mut Channel,
    rng: &mut RNG,
) -> eyre::Result<U8x16> {
    // The protocol works as follows:
    //
    // 1. The sender generates its seed `s₀`, computes `c ← H(s₀)`, and sends
    //    `c` to the receiver.
    // 2. The receiver generates its seed `s₁` and sends `s₁` to the sender.
    // 3. The sender sends `s₀` to the receiver, who checks that `H(s₀) = c`,
    //    aborting if not.
    // 4. Both parties output `s₀ ⊕ s₁`.
    let mut hasher = blake3::Hasher::new();
    let seed_mine = rng.r#gen::<U8x16>();
    let seed = match P::WHICH {
        swanky_party::WhichParty::Prover(_) => {
            hasher.update(&seed_mine.to_bytes());
            let com = *hasher.finalize().as_bytes();
            channel.write(&com)?;
            let seed_theirs = channel.read()?;
            channel.write(&seed_mine)?;
            seed_mine ^ seed_theirs
        }
        swanky_party::WhichParty::Verifier(_) => {
            let com = channel.read::<[u8; 32]>()?;
            channel.write(&seed_mine)?;
            let seed_theirs = channel.read::<U8x16>()?;
            hasher.update(&seed_theirs.to_bytes());
            let com_ = *hasher.finalize().as_bytes();
            eyre::ensure!(com_ == com, "Commitment check failed");
            seed_mine ^ seed_theirs
        }
    };
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_aes_rng::AesRng;
    use swanky_party::{Prover, Verifier};

    #[test]
    fn random_seed_works() {
        let mut rng_a = AesRng::new();
        let mut rng_b = AesRng::new();
        let (result_a, result_b) = swanky_channel::local::local_channel_pair(
            |c| random_seed::<Prover, _>(c, &mut rng_a),
            |c| random_seed::<Verifier, _>(c, &mut rng_b),
        )
        .unwrap();
        assert_eq!(result_a, result_b);
    }

    #[test]
    fn malicious_sender_fails() {
        let mut rng_a = AesRng::new();
        let mut rng_b = AesRng::new();
        let result = swanky_channel::local::local_channel_pair(
            |c| {
                let seed_mine = rng_a.r#gen::<U8x16>();
                let com = rng_a.r#gen::<[u8; 32]>();
                c.write(&com)?;
                let seed_theirs = c.read()?;
                c.write(&seed_mine)?;
                Ok(seed_mine ^ seed_theirs)
            },
            |c| random_seed::<Verifier, _>(c, &mut rng_b),
        );
        assert!(result.is_err());
    }

    #[test]
    fn random_i32_works() {
        let mut rng_a = AesRng::new();
        let mut rng_b = AesRng::new();
        let (result_a, result_b) = swanky_channel::local::local_channel_pair(
            |c| random::<Prover, i32, _>(c, &mut rng_a),
            |c| random::<Verifier, i32, _>(c, &mut rng_b),
        )
        .unwrap();
        assert_eq!(result_a, result_b);
    }
}
