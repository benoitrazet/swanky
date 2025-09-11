//! Authenticated shares.
//!
//! An authenticated share $`\langle x \rangle := \langle x_1 | x_2 \rangle`$
//! is a pair of authenticated bits $`[x_1]_A`$, $`[x_2]_B`$, where $`[x_1]_A`$
//! denotes that $`[x_1]`$ is an authenticated bit held by Party A, and likewise,
//! $`[x_2]_B`$ is an authenticated bit held by Party B. We define $`x = x_1
//! \oplus x_2`$.
//!
//! This module provides authenticated shares through the [`AuthShare`] type,
//! alongside [`AuthShareGenerator`] for generating such shares.
//!
//! # Details
//!
//! [`AuthShare`]s are simply pairs of [`AuthBit`]s where each party plays the
//! role of the prover for one of the bits, and verifier for the other.
//!
//! # Example
//!
//! ```
//! # use rand::Rng;
//! # use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
//! # use swanky_field_binary::F2;
//! # use swanky_ot_alsz_kos::kos;
//! # use swanky_party::{Prover, Verifier, IS_PROVER, IS_VERIFIER};
//! # use swanky_party::either::PartyEitherCopy;
//! # use swanky_party::private::VerifierPrivate;
//! # fn main() -> eyre::Result<()> {
//! let nshares = 1000;
//! let (bits_a, bits_b) = swanky_channel::local::local_channel_pair(
//!     |c| {
//!         // Party A (the "prover").
//!         let mut rng = swanky_aes_rng::AesRng::new();
//!         let mut authshares: Vec<AuthShare<Prover>> = vec![];
//!         let mut bits: Vec<F2> = vec![];
//!         let mut generator: AuthShareGenerator<_, kos::Sender, kos::Receiver> = AuthShareGenerator::new(c, &mut rng)?;
//!         generator.generate(nshares, &mut authshares, c, &mut rng)?;
//!         generator.open(&authshares, &mut bits, c)?;
//!         Ok(bits)
//!     },
//!     |c| {
//!         // Party B (the "verifier").
//!         let mut rng = swanky_aes_rng::AesRng::new();
//!         let mut authshares: Vec<AuthShare<Verifier>> = vec![];
//!         let mut bits: Vec<F2> = vec![];
//!         let mut generator: AuthShareGenerator<_, kos::Sender, kos::Receiver> = AuthShareGenerator::new(c, &mut rng)?;
//!         generator.generate(nshares, &mut authshares, c, &mut rng)?;
//!         generator.open(&authshares, &mut bits, c)?;
//!         Ok(bits)
//!     }
//! )?;
//! assert_eq!(bits_a, bits_b);
//! # Ok(())
//! # }

//! ```

use crate::authbits::{AuthBit, AuthBitGenerator};
use rand::{CryptoRng, Rng};
use swanky_adversary::Malicious;
use swanky_channel::Channel;
use swanky_field_binary::F2;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
use swanky_party::{
    IS_PROVER, IS_VERIFIER, Party, Prover, Verifier, WhichParty,
    either::{PartyEither, PartyEitherCopy},
    private::{VerifierPrivate, VerifierPrivateCopy},
};
use vectoreyes::U8x16;

/// Party A.
///
/// This is a type-alias for [`Prover`] and is useful to clarify the role of a
/// given [`AuthShare`].
pub type PartyA = Prover;
/// Party B.
///
/// This is a type-alias for [`Verifier`] and is useful to clarify the role of a
/// given [`AuthShare`].
pub type PartyB = Verifier;

/// An authenticated share.
///
/// See [`crate::authshares`] for details. [`AuthShare`]s can be generated using
/// [`AuthShareGenerator`].
#[derive(Clone, Copy)]
pub struct AuthShare<P: Party> {
    /// Party A's side of the authenticated share.
    party_a: PartyEitherCopy<P, AuthBit<Prover>, AuthBit<Verifier>>,
    /// Party B's side of the authenticated share.
    party_b: PartyEitherCopy<P, AuthBit<Verifier>, AuthBit<Prover>>,
}

impl<P: Party> AuthShare<P> {
    /// The given party's bit.
    ///
    /// This corresponds to $`x_1`$ for Party A (the "prover"), and $`x_2`$
    /// for Party B (the "verifier").
    pub fn bit(self) -> F2 {
        match P::WHICH {
            WhichParty::Prover(ev) => self.party_a.prover_into(ev).bit().into_inner(IS_PROVER),
            WhichParty::Verifier(ev) => self.party_b.verifier_into(ev).bit().into_inner(IS_PROVER),
        }
    }

    /// The given party's key.
    ///
    /// This corresponds to $`K[x_2]`$ for Party A (the "prover"), and
    /// $`K[x_1]`$ for Party B (the "verifier").
    pub fn key(self) -> U8x16 {
        match P::WHICH {
            WhichParty::Prover(ev) => self.party_b.prover_into(ev).key().into_inner(IS_VERIFIER),
            WhichParty::Verifier(ev) => {
                self.party_a.verifier_into(ev).key().into_inner(IS_VERIFIER)
            }
        }
    }

    /// The given party's MAC.
    ///
    /// This corresponds to $`M[x_1]`$ for Party A (the "prover"), and
    /// $`M[x_2]`$ for Party B (the "verifier").
    pub fn mac(self) -> U8x16 {
        match P::WHICH {
            WhichParty::Prover(ev) => self.party_a.prover_into(ev).mac().into_inner(IS_PROVER),
            WhichParty::Verifier(ev) => self.party_b.verifier_into(ev).mac().into_inner(IS_PROVER),
        }
    }
}

impl<P: Party> core::ops::BitXor for AuthShare<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        match P::WHICH {
            WhichParty::Prover(ev) => AuthShare {
                party_a: PartyEitherCopy::prover_new(
                    ev,
                    self.party_a.prover_into(ev) ^ rhs.party_a.prover_into(ev),
                ),
                party_b: PartyEitherCopy::prover_new(
                    ev,
                    self.party_b.prover_into(ev) ^ rhs.party_b.prover_into(ev),
                ),
            },
            WhichParty::Verifier(ev) => AuthShare {
                party_a: PartyEitherCopy::verifier_new(
                    ev,
                    self.party_a.verifier_into(ev) ^ rhs.party_a.verifier_into(ev),
                ),
                party_b: PartyEitherCopy::verifier_new(
                    ev,
                    self.party_b.verifier_into(ev) ^ rhs.party_b.verifier_into(ev),
                ),
            },
        }
    }
}

/// A type for generating [`AuthShare`]s.
pub struct AuthShareGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    party_a:
        PartyEither<P, AuthBitGenerator<Prover, OTS, OTR>, AuthBitGenerator<Verifier, OTS, OTR>>,
    party_b:
        PartyEither<P, AuthBitGenerator<Verifier, OTS, OTR>, AuthBitGenerator<Prover, OTS, OTR>>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthShareGenerator<P, OTS, OTR>
{
    /// Create a new [`AuthShareGenerator`].
    pub fn new<RNG: CryptoRng + Rng>(channel: &mut Channel, mut rng: RNG) -> eyre::Result<Self> {
        let delta = rng.r#gen::<U8x16>();
        Self::new_with_delta(delta, channel, rng)
    }

    /// Create a new [`AuthShareGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG: CryptoRng + Rng>(
        delta: U8x16,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<Self> {
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = AuthBitGenerator::<Prover, OTS, OTR>::new(channel, &mut rng)?;
                let party_b = AuthBitGenerator::<Verifier, OTS, OTR>::new_with_delta(
                    VerifierPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::prover_new(ev, party_a),
                    party_b: PartyEither::prover_new(ev, party_b),
                })
            }
            WhichParty::Verifier(ev) => {
                let party_a = AuthBitGenerator::<Verifier, OTS, OTR>::new_with_delta(
                    VerifierPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                let party_b = AuthBitGenerator::<Prover, OTS, OTR>::new(channel, &mut rng)?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::verifier_new(ev, party_a),
                    party_b: PartyEither::verifier_new(ev, party_b),
                })
            }
        }
    }

    /// Generate a vector of authenticated shares.
    ///
    /// The `nshares` generated shares are [`Vec::extend`]ed into `shares`.
    pub fn generate<RNG: CryptoRng + Rng>(
        &mut self,
        nshares: usize,
        shares: &mut Vec<AuthShare<P>>,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> eyre::Result<()> {
        let bits: Vec<_> = (0..nshares).map(|_| rng.r#gen::<F2>()).collect();

        let mut party_a_auth_bits = Vec::with_capacity(nshares);
        let mut party_b_auth_bits = Vec::with_capacity(nshares);

        let bits = PartyEitherCopy::prover_new(IS_PROVER, bits.as_slice());
        let nshares = PartyEitherCopy::verifier_new(IS_VERIFIER, nshares);
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = self.party_a.as_mut().prover_into(ev);
                let party_b = self.party_b.as_mut().prover_into(ev);

                party_a.generate(bits, &mut party_a_auth_bits, channel, rng)?;
                party_b.generate(nshares, &mut party_b_auth_bits, channel, rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::prover_new(ev, party_a_val),
                        party_b: PartyEitherCopy::prover_new(ev, party_b_val),
                    },
                ));
            }
            WhichParty::Verifier(ev) => {
                let party_a = self.party_a.as_mut().verifier_into(ev);
                let party_b = self.party_b.as_mut().verifier_into(ev);

                party_a.generate(nshares, &mut party_b_auth_bits, channel, rng)?;
                party_b.generate(bits, &mut party_a_auth_bits, channel, rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::verifier_new(ev, party_b_val),
                        party_b: PartyEitherCopy::verifier_new(ev, party_a_val),
                    },
                ));
            }
        }
        Ok(())
    }

    /// Open the authenticated shares in `shares`.
    ///
    /// This corresponds to opening all the authenticated bits that make up the
    /// authenticated shares. The resulting opened combined shares are
    /// [`Vec::push`]ed to `outputs`.
    pub fn open(
        &self,
        shares: &[AuthShare<P>],
        outputs: &mut Vec<F2>,
        channel: &mut Channel,
    ) -> eyre::Result<()> {
        // We only want to use the bits that are added to `outputs`, so we grab the
        // initial length here and use it to avoid touching anything already
        // existing in `outputs`.
        let output_starting_len = outputs.len();
        let (party_a_shares, party_b_shares): (Vec<_>, Vec<_>) = shares
            .iter()
            .map(|authshare| (authshare.party_a, authshare.party_b))
            .unzip();
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = self.party_a.as_ref().prover_into(ev);
                let party_b = self.party_b.as_ref().prover_into(ev);

                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).prover_into(ev);
                party_a.open(party_a_shares, VerifierPrivate::empty(IS_PROVER), channel)?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).prover_into(ev);
                party_b.open(party_b_shares, VerifierPrivate::new(outputs), channel)?;
                for (bit_a, bit_b) in party_a_shares
                    .iter()
                    .zip(outputs[output_starting_len..].iter_mut())
                {
                    *bit_b += bit_a.bit().into_inner(IS_PROVER);
                }
            }
            WhichParty::Verifier(ev) => {
                let party_a = self.party_a.as_ref().verifier_into(ev);
                let party_b = self.party_b.as_ref().verifier_into(ev);

                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).verifier_into(ev);
                party_a.open(party_a_shares, VerifierPrivate::new(outputs), channel)?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).verifier_into(ev);
                party_b.open(party_b_shares, VerifierPrivate::empty(IS_PROVER), channel)?;
                for (bit_a, bit_b) in outputs[output_starting_len..]
                    .iter_mut()
                    .zip(party_b_shares.iter())
                {
                    *bit_a += bit_b.bit().into_inner(IS_PROVER);
                }
            }
        }
        Ok(())
    }

    /// The $`\Delta`$ value used to validate the other party's share.
    pub fn delta(&self) -> U8x16 {
        match P::WHICH {
            WhichParty::Prover(ev) => self
                .party_b
                .as_ref()
                .prover_into(ev)
                .delta()
                .into_inner(IS_VERIFIER),
            WhichParty::Verifier(ev) => self
                .party_a
                .as_ref()
                .verifier_into(ev)
                .delta()
                .into_inner(IS_VERIFIER),
        }
    }

    /// Compute $`\langle x \rangle \oplus c`$, where $`c`$ is a public
    /// constant.
    ///
    /// This works by computing $`[x_2]_B \oplus c`$, where $`[x_2]_B`$ is the
    /// authenticated bit held by Party B.
    pub fn xor_with_const(&self, authshare: AuthShare<P>, bit: F2) -> AuthShare<P> {
        match P::WHICH {
            WhichParty::Prover(ev) => AuthShare {
                party_a: authshare.party_a,
                party_b: PartyEitherCopy::prover_new(
                    ev,
                    self.party_b
                        .as_ref()
                        .prover_into(ev)
                        .xor_with_const(authshare.party_b.prover_into(ev), bit),
                ),
            },
            WhichParty::Verifier(ev) => AuthShare {
                party_a: authshare.party_a,
                party_b: PartyEitherCopy::verifier_new(
                    ev,
                    self.party_b
                        .as_ref()
                        .verifier_into(ev)
                        .xor_with_const(authshare.party_b.verifier_into(ev), bit),
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use swanky_aes_rng::AesRng;
    use swanky_ot_alsz_kos::kos;

    /// Generates `AuthShare`s, outputting the produced `AuthShare`s and their
    /// associated generators.
    fn generate(
        nshares: usize,
        seed_party_a: U8x16,
        seed_party_b: U8x16,
    ) -> (
        Vec<AuthShare<PartyA>>,
        Vec<AuthShare<PartyB>>,
        AuthShareGenerator<PartyA, kos::Sender, kos::Receiver>,
        AuthShareGenerator<PartyB, kos::Sender, kos::Receiver>,
    ) {
        let mut output_a: Vec<AuthShare<PartyA>> = vec![];
        let mut output_b: Vec<AuthShare<PartyB>> = vec![];
        let (generator_a, generator_b) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::from_seed(seed_party_a);
                let mut generator =
                    AuthShareGenerator::<PartyA, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                generator.generate(nshares, &mut output_a, c, &mut rng)?;
                Ok(generator)
            },
            |c| {
                let mut rng = AesRng::from_seed(seed_party_b);
                let mut generator =
                    AuthShareGenerator::<PartyB, kos::Sender, kos::Receiver>::new(c, &mut rng)?;
                generator.generate(nshares, &mut output_b, c, &mut rng)?;
                Ok(generator)
            },
        )
        .unwrap();
        (output_a, output_b, generator_a, generator_b)
    }

    /// Validates vectors of `AuthShare`s using their associated generators.
    fn validate(
        generator_a: &AuthShareGenerator<PartyA, kos::Sender, kos::Receiver>,
        generator_b: &AuthShareGenerator<PartyB, kos::Sender, kos::Receiver>,
        output_a: Vec<AuthShare<PartyA>>,
        output_b: Vec<AuthShare<PartyB>>,
    ) -> (bool, bool) {
        swanky_channel::local::local_channel_pair(
            |c| {
                let mut outputs = vec![];
                let result = generator_a.open(&output_a, &mut outputs, c);
                Ok(result.is_ok())
            },
            |c| {
                let mut outputs = vec![];
                let result = generator_b.open(&output_b, &mut outputs, c);
                Ok(result.is_ok())
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(nshares in 1..1000usize,
                                   seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let (output_a, output_b, generator_a, generator_b) = generate(nshares, U8x16::from(seed_party_a), U8x16::from(seed_party_b));
            let (validation_a, validation_b) =
                validate(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(validation_a);
            prop_assert!(validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn wrong_output_fails(nshares in 1..1000usize,
                              seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = AesRng::from_seed(U8x16::from(seed_party_b));
            let (output_a, _, generator_a, generator_b) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            let (_output_c, output_d, _, _) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            let (validation_a, validation_b) =
                validate(&generator_a, &generator_b, output_a, output_d);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_party_b_share_fails(nshares in 1..1000usize, index in any::<proptest::sample::Index>(),
                                        seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = AesRng::from_seed(U8x16::from(seed_party_b));
            let index = index.index(nshares);
            let (output_a, mut output_b, generator_a, generator_b) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            let (_output_c, output_d, _, _) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            output_b[index] = output_d[index];
            let (validation_a, validation_b) =
                validate(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_party_a_share_fails(nshares in 1..1000usize, index in any::<proptest::sample::Index>(),
                                        seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(U8x16::from(seed_party_a));
            let mut rng_b = AesRng::from_seed(U8x16::from(seed_party_b));
            let index = index.index(nshares);
            let (mut output_a, output_b, generator_a, generator_b) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            let (output_c, _output_d, _, _) = generate(nshares, rng_a.r#gen::<U8x16>(), rng_b.r#gen::<U8x16>());
            output_a[index] = output_c[index];
            let (validation_a, validation_b) =
                validate(&generator_a, &generator_b, output_a, output_b);
            prop_assert!(!validation_a);
            prop_assert!(!validation_b);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn xor_with_const_works(constants in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_party_a in any::<u128>(), seed_party_b in any::<u128>()) {
            let constants: Vec<F2> = constants.into_iter().map(F2::from).collect();
            let count = constants.len();
            let (output_a, output_b, generator_a, generator_b) = generate(count, U8x16::from(seed_party_a), U8x16::from(seed_party_b));
            for ((a, b), bit) in output_a
                .into_iter()
                .zip(output_b.into_iter())
                .zip(constants)
            {
                let new_a = generator_a.xor_with_const(a, bit);
                let new_b = generator_b.xor_with_const(b, bit);
                // The new authenticated share should still validate.
                let (validation_a, validation_b) =
                    validate(&generator_a, &generator_b, vec![new_a], vec![new_b]);
                prop_assert!(validation_a);
                prop_assert!(validation_b);
                // The new authenticated share should equal `⟨x⟩ ⊕ c`.
                prop_assert_eq!(a.bit() + b.bit() + bit, new_a.bit() + new_b.bit());
            }
        }
    }
}
