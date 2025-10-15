//! Authenticated bits.
//!
//! See [`crate`] for a high-level description of authenticated bits. This
//! module provides the [`AuthBit`] type, which represents an authenticated bit,
//! alongside the [`AuthBitGenerator`] type, which provides a means for
//! generating a vector of [`AuthBit`]s.
//!
//! # Details
//!
//! The protocol is briefly described by Nielsen et al. [^1] in Section 3.1, but
//! essentially, authenticated bits are _just_ the outputs of correlated
//! oblivious transfer (called Δ-ROT in the paper).
//!
//! In more detail, to generate [`AuthBit`]s, the prover holds a vector of bits
//! $`b_i`$ of length $`n`$, and the verifier holds a long term key $`\Delta`$.
//!
//! The prover and verifier perform a Δ-ROT per bit so that the prover receives
//! $`M_i := K_i \oplus b_i \Delta`$ and the verifier receives $`K_i`$. In other
//! words:
//!
//! - If $`b_i = 1`$, the prover receives $`M_{i,1} := K_i \oplus \Delta`$.
//! - If $`b_i = 0`$, the prover receives $`M_{i,0} := K_i`$.
//!
//! The verifier receives both $`M_{i,0}`$ and $`M_{i,1}`$.
//!
//! To open an authenticated bit, the prover sends $`(b_i, M_i)`$ to the
//! verifier and the verifier checks that $`M_i = K_i \oplus b \Delta`$.
//!
//! # Example
//!
//! Below is an example that shows the generation and opening of 10
//! [`AuthBit`]s.
//!
//! ```
//! # use rand::Rng;
//! # use swanky_authenticated_bits::authbits::{AuthBit, AuthBitGenerator};
//! # use swanky_field_binary::F2;
//! # use swanky_party::{Prover, Verifier, IS_PROVER, IS_VERIFIER};
//! # use swanky_party::either::PartyEitherCopy;
//! # use swanky_party::private::VerifierPrivate;
//! # fn main() -> eyre::Result<()> {
//! let (bits_prover, bits_verifier) = swanky_channel::local::local_channel_pair(
//!     |c| {
//!         // The prover.
//!         let mut rng = swanky_aes_rng::AesRng::new();
//!         let bits = rng.r#gen::<[F2; 10]>();
//!         let mut authbits: Vec<AuthBit<Prover>> = vec![];
//!         let mut generator: AuthBitGenerator<_> = AuthBitGenerator::new(c, &mut rng)?;
//!         generator.generate(PartyEitherCopy::prover_new(IS_PROVER, &bits), &mut authbits, c, &mut rng)?;
//!         generator.open(&authbits, VerifierPrivate::empty(IS_PROVER), c)?;
//!         Ok(bits.to_vec())
//!     },
//!     |c| {
//!         // The verifier.
//!         let mut rng = swanky_aes_rng::AesRng::new();
//!         let count = 10;
//!         let mut bits = vec![];
//!         let mut authbits: Vec<AuthBit<Verifier>> = vec![];
//!         let mut generator: AuthBitGenerator<_> = AuthBitGenerator::new(c, &mut rng)?;
//!         generator.generate(PartyEitherCopy::verifier_new(IS_VERIFIER, count), &mut authbits, c, &mut rng)?;
//!         generator.open(&authbits, VerifierPrivate::new(&mut bits), c)?;
//!         Ok(bits)
//!     }
//! )?;
//! assert_eq!(bits_prover, bits_verifier);
//! # Ok(())
//! # }
//! ```
//!
//! [^1]: J.B. Nielsen, T. Schneider, R. Trifiletti. "Constant Round Maliciously
//!     Secure 2PC with Function-independent Preprocessing using LEGO".
//!     <https://eprint.iacr.org/2016/1069.pdf>

use rand::{CryptoRng, Rng};
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer, F128b};
use swanky_ot_alsz_kos::kos;
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender, Receiver, Sender};
use swanky_party::{
    Party, WhichParty,
    either::{PartyEither, PartyEitherCopy},
    private::{ProverPrivateCopy, VerifierPrivate, VerifierPrivateCopy},
};
use swanky_serialization::{SequenceDeserializer, SequenceSerializer};
use vectoreyes::U8x16;

/// The prover's part of the authentication bit.
///
/// The prover holds a bit that they wish to authenticate and receive a MAC
/// which corresponds to that authentication.
#[derive(Clone, Copy)]
struct ProverAuthBit {
    /// MAC authenticating the bit.
    mac: U8x16,
    /// The authenticated bit.
    bit: F2,
}
/// The verifier's part of the authentication bit.
///
/// The verifier holds a local `key` that verifies the integrity of the prover's
/// MAC.
#[derive(Clone, Copy)]
struct VerifierAuthBit {
    /// Key authenticating the prover's MAC.
    key: U8x16,
}
/// An authenticated bit.
///
/// See [`crate::authbits`] for details. [`AuthBit`]s can be generated using
/// [`AuthBitGenerator`].
#[derive(Clone, Copy)]
pub struct AuthBit<P: Party>(PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>);

impl<P: Party> AuthBit<P> {
    /// The [`ProverAuthBit`] component.
    fn to_prover(self) -> ProverPrivateCopy<P, ProverAuthBit> {
        self.0.into_privates().0
    }
    /// The [`VerifierAuthBit`] component.
    fn to_verifier(self) -> VerifierPrivateCopy<P, VerifierAuthBit> {
        self.0.into_privates().1
    }
    /// Output the verifier's key associated with this [`AuthBit`].
    pub fn key(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.to_verifier().map(|vab| vab.key)
    }
    /// Output the prover's MAC associated with this [`AuthBit`].
    pub fn mac(&self) -> ProverPrivateCopy<P, U8x16> {
        self.to_prover().map(|vab| vab.mac)
    }
    /// Output the prover's bit associated with this [`AuthBit`].
    pub fn bit(&self) -> ProverPrivateCopy<P, F2> {
        self.to_prover().map(|vab| vab.bit)
    }
}

/// XOR two authenticated bits. Linear operations on authenticated bits are "free"
/// (i.e. can be done locally).
impl<P: Party> std::ops::BitXor for AuthBit<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let pairs = self.0.zip(rhs.0);
        AuthBit(pairs.map(
            |(lhs, rhs)| ProverAuthBit {
                mac: lhs.mac ^ rhs.mac,
                bit: lhs.bit + rhs.bit,
            },
            |(lhs, rhs)| VerifierAuthBit {
                key: lhs.key ^ rhs.key,
            },
        ))
    }
}

/// A type for generating [`AuthBit`]s.
///
/// For authenticated bit _verifiers_, the generator contains the particular
/// $`\Delta`$ value to verify against. This means that generated [`AuthBit`]s
/// _must_ be opened using the same generator that generated them! Odd behavior
/// may result if a different generator is used: when verifying one bits,
/// verification will fail (with overwhelming probability), but when verifying
/// zero bits, verification will not (because the $`\Delta`$ value is never used
/// in the verification of a zero bit)!
pub struct AuthBitGenerator<P: Party> {
    /// The verifier's global $`\Delta`$.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party-specific correlated OT instantiation.
    ot: PartyEither<P, kos::Receiver, kos::Sender>,
}

impl<P: Party> AuthBitGenerator<P> {
    /// Create a new [`AuthBitGenerator`].
    ///
    /// The verifier's $`\Delta`$ value is randomly generated using `rng`.
    pub fn new<RNG>(channel: &mut Channel, mut rng: RNG) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        match P::WHICH {
            WhichParty::Prover(e) => {
                Self::new_with_delta(VerifierPrivateCopy::empty(e), channel, rng)
            }
            WhichParty::Verifier(_e) => {
                let delta = rng.r#gen::<U8x16>();
                Self::new_with_delta(VerifierPrivateCopy::new(delta), channel, rng)
            }
        }
    }

    /// Create a new [`AuthBitGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG>(
        delta: VerifierPrivateCopy<P, U8x16>,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        let result = match P::WHICH {
            WhichParty::Prover(e) => AuthBitGenerator {
                delta: VerifierPrivateCopy::empty(e),
                ot: PartyEither::prover_new(e, kos::Receiver::init(channel, &mut rng)?),
            },
            WhichParty::Verifier(e) => AuthBitGenerator {
                delta: VerifierPrivateCopy::new(delta.into_inner(e)),
                ot: PartyEither::verifier_new(e, kos::Sender::init(channel, &mut rng)?),
            },
        };
        Ok(result)
    }

    /// Generate a vector of authenticated bits.
    ///
    /// The prover supplies the bits to authenticate, and the verifier specifies
    /// the number of bits. The resulting authenticated bits are
    /// [`Vec::extend`]ed into `out`.
    pub fn generate<RNG>(
        &mut self,
        bits_in: PartyEitherCopy<P, &[F2], usize>,
        out: &mut Vec<AuthBit<P>>,
        mut channel: &mut Channel,
        rng: &mut RNG,
    ) -> eyre::Result<()>
    where
        RNG: CryptoRng + Rng,
    {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let bits = bits_in.prover_into(e);
                let macs = self.ot.as_mut().prover_into(e).receive_correlated(
                    &mut channel,
                    // TODO: Once OT uses F2 instead of bool this line won't be necessary.
                    &bits.iter().map(|b| bool::from(*b)).collect::<Vec<bool>>(),
                    rng,
                )?;

                out.extend(bits.iter().zip(macs).map(|(bit, mac)| {
                    AuthBit(PartyEitherCopy::prover_new(
                        e,
                        ProverAuthBit { bit: *bit, mac },
                    ))
                }));
                Ok(())
            }
            WhichParty::Verifier(e) => {
                let delta = self.delta().into_inner(e);
                let keys = self.ot.as_mut().verifier_into(e).send_correlated(
                    &mut channel,
                    bits_in.verifier_into(e),
                    delta,
                    rng,
                )?;
                out.extend(
                    keys.into_iter().map(|key| {
                        AuthBit(PartyEitherCopy::verifier_new(e, VerifierAuthBit { key }))
                    }),
                );

                Ok(())
            }
        }
    }

    /// Open the authenticated bits in `authbits`.
    ///
    /// This corresponds to the prover sending $`(b, M)`$ to the verifier, who
    /// checks that $`K = M \oplus b \Delta`$. The resulting opened bits are
    /// [`Vec::push`]ed to `outputs`.
    pub fn open(
        &self,
        authbits: &[AuthBit<P>],
        outputs: VerifierPrivate<P, &mut Vec<F2>>,
        channel: &mut Channel,
    ) -> eyre::Result<()> {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let mut bit_ser: F2BitSerializer =
                    SequenceSerializer::new(&mut channel.as_std_io())?;
                for b in authbits.iter() {
                    bit_ser.write(channel.as_std_io(), b.bit().into_inner(e))?;
                }
                bit_ser.finish(channel.as_std_io())?;

                for ab in authbits.iter() {
                    channel.write_bytes(ab.mac().into_inner(e).as_ref())?;
                }
            }
            WhichParty::Verifier(e) => {
                let mut bit_ser: F2BitDeserializer =
                    SequenceDeserializer::new(channel.as_std_io())?;
                let bits_ = outputs.into_inner(e);
                // We only want to validate the bits we added to the `outputs`
                // vector, so we save the existing length so we can only
                // validate the [`Vec::push`]ed bits.
                let outputs_initial_len = bits_.len();
                for _ in 0..authbits.len() {
                    bits_.push(bit_ser.read(channel.as_std_io())?);
                }
                let mut validation = true;
                for (ab, bit) in authbits.iter().zip(bits_[outputs_initial_len..].iter()) {
                    let mac = channel.read::<U8x16>()?;

                    validation &= mac
                        == if F2::ONE == *bit {
                            ab.key().into_inner(e) ^ self.delta().into_inner(e)
                        } else {
                            ab.key().into_inner(e)
                        };
                }
                if !validation {
                    return Err(eyre::Error::msg("Validation check failed"));
                }
            }
        }
        Ok(())
    }

    /// The verifier's $`\Delta`$ value.
    pub fn delta(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.delta
    }

    /// Compute $`[b] \oplus c`$, where $`c`$ is a public constant.
    ///
    /// This maps the prover's values $`(b, M)`$ to $`(b \oplus c, M)`$,
    /// and maps the verifier's value $`K`$ to $`K \oplus c \Delta`$.
    pub fn xor_with_const(&self, authbit: AuthBit<P>, bit: F2) -> AuthBit<P> {
        match P::WHICH {
            WhichParty::Prover(ev) => AuthBit(PartyEitherCopy::prover_new(
                ev,
                ProverAuthBit {
                    mac: authbit.mac().into_inner(ev),
                    bit: authbit.bit().into_inner(ev) + bit,
                },
            )),
            WhichParty::Verifier(ev) => AuthBit(PartyEitherCopy::verifier_new(
                ev,
                VerifierAuthBit {
                    key: authbit.key().into_inner(ev)
                        ^ U8x16::from(bit * F128b::from(self.delta().into_inner(ev))),
                },
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use swanky_aes_rng::AesRng;
    use swanky_field::FiniteRing;
    use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier, either::PartyEitherCopy};

    fn generators(
        mut rng_a: &mut AesRng,
        mut rng_b: &mut AesRng,
    ) -> (AuthBitGenerator<Prover>, AuthBitGenerator<Verifier>) {
        swanky_channel::local::local_channel_pair(
            |c| AuthBitGenerator::<Prover>::new(c, &mut rng_a),
            |c| AuthBitGenerator::<Verifier>::new(c, &mut rng_b),
        )
        .unwrap()
    }

    /// Validates pairs of prover and verifier `AuthBit`s.
    fn validate(pr: &[AuthBit<Prover>], vr: &[AuthBit<Verifier>], delta: U8x16) -> bool {
        assert!(!pr.is_empty());
        assert!(!vr.is_empty());
        assert_eq!(pr.len(), vr.len());

        pr.iter()
            .zip(vr)
            .map(|(ab_pr, ab_vr)| {
                ab_pr.mac().into_inner(IS_PROVER)
                    == (if ab_pr.bit().into_inner(IS_PROVER) == F2::ONE {
                        ab_vr.key().into_inner(IS_VERIFIER) ^ delta
                    } else {
                        ab_vr.key().into_inner(IS_VERIFIER)
                    })
            })
            .reduce(|b1, b2| b1 && b2)
            .unwrap()
    }

    /// Generates `AuthBit`s, outputting the produced `AuthBit`s and their
    /// associated generators. If `tamper_mac` is true, tamper with the prover's
    /// MAC. If `tamper_key` is true, tamper with the verifier's key.
    fn generate(
        bits_in: &[F2],
        generator_a: &mut AuthBitGenerator<Prover>,
        generator_b: &mut AuthBitGenerator<Verifier>,
        mut rng_a: &mut AesRng,
        mut rng_b: &mut AesRng,
        tamper_mac: bool,
        tamper_key: bool,
    ) -> (Vec<AuthBit<Prover>>, Vec<AuthBit<Verifier>>) {
        assert!(!bits_in.is_empty());
        swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut outputs = vec![];
                let bits = PartyEitherCopy::prover_new(IS_PROVER, bits_in);
                generator_a.generate(bits, &mut outputs, channel_pr, &mut rng_a)?;
                if tamper_mac {
                    // Tamper the MAC of the first `AuthBit`.
                    outputs[0] = AuthBit(PartyEitherCopy::prover_new(
                        IS_PROVER,
                        ProverAuthBit {
                            bit: outputs[0].bit().into_inner(IS_PROVER),
                            mac: rng_a.r#gen(),
                        },
                    ));
                }
                generator_a.open(&outputs, VerifierPrivate::empty(IS_PROVER), channel_pr)?;
                Ok(outputs)
            },
            |channel_vr| {
                let mut outputs = vec![];
                let count = PartyEitherCopy::verifier_new(IS_VERIFIER, bits_in.len());
                generator_b.generate(count, &mut outputs, channel_vr, &mut rng_b)?;
                if tamper_key {
                    // Tamper the key of the first `AuthBit`.
                    outputs[0] = AuthBit(PartyEitherCopy::verifier_new(
                        IS_VERIFIER,
                        VerifierAuthBit { key: rng_b.r#gen() },
                    ));
                }
                let mut output = vec![];
                let validation =
                    generator_b.open(&outputs, VerifierPrivate::new(&mut output), channel_vr);
                // The generated bits should always be valid when no tampering happens.
                if !tamper_mac && !tamper_key {
                    assert!(validation.is_ok());
                } else {
                    assert!(validation.is_err());
                }
                Ok(outputs)
            },
        )
        .unwrap()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn xor_with_const_works(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                public_bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                seed_prover in any::<u128>(),
                                seed_verifier in any::<u128>()) {
            let mut rng_pr = AesRng::from_seed(seed_prover.into());
            let mut rng_vr = AesRng::from_seed(seed_verifier.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let public_bits: Vec<F2> = public_bits.into_iter().map(F2::from).collect();
            let (mut generator_pr, mut generator_vr) = generators(&mut rng_pr, &mut rng_vr);
            let (output_pr, output_vr) = generate(&bits, &mut generator_pr, &mut generator_vr, &mut rng_pr, &mut rng_vr, false, false);
            for ((authbit_pr, authbit_vr), public_bit) in output_pr
                .into_iter()
                .zip(output_vr.into_iter())
                .zip(public_bits.into_iter())
            {
                let new_authbit_pr = generator_pr.xor_with_const(authbit_pr, public_bit);
                let new_authbit_vr = generator_vr.xor_with_const(authbit_vr, public_bit);
                // The new authenticated bits should still validate.
                let validation = validate(
                    &[new_authbit_pr],
                    &[new_authbit_vr],
                    generator_vr.delta().into_inner(IS_VERIFIER),
                );
                prop_assert!(validation);
                // The new authenticated bits should equal `bit ^ public_bit`.
                prop_assert_eq!(
                    new_authbit_pr.bit().into_inner(IS_PROVER),
                    authbit_pr.bit().into_inner(IS_PROVER) + public_bit
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn honest_generation_works(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                   seed_prover in any::<u128>(),
                                   seed_verifier in any::<u128>()) {
            let mut rng_pr = AesRng::from_seed(seed_prover.into());
            let mut rng_vr = AesRng::from_seed(seed_verifier.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_pr, mut generator_vr) = generators(&mut rng_pr, &mut rng_vr);
            let (output_pr, output_vr) = generate(&bits, &mut generator_pr, &mut generator_vr, &mut rng_pr, &mut rng_vr, false, false);
            let validation = validate(
                &output_pr,
                &output_vr,
                generator_vr.delta().into_inner(IS_VERIFIER),
            );
            prop_assert!(validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_mac_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                              seed_prover in any::<u128>(),
                              seed_verifier in any::<u128>()) {
            let mut rng_pr = AesRng::from_seed(seed_prover.into());
            let mut rng_vr = AesRng::from_seed(seed_verifier.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_pr, mut generator_vr) = generators(&mut rng_pr, &mut rng_vr);
            let (output_pr, output_vr) = generate(&bits, &mut generator_pr, &mut generator_vr, &mut rng_pr, &mut rng_vr, true, false);
            let validation = validate(
                &output_pr,
                &output_vr,
                generator_vr.delta().into_inner(IS_VERIFIER),
            );
            prop_assert!(!validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_key_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                              seed_prover in any::<u128>(),
                              seed_verifier in any::<u128>()) {
            let mut rng_pr = AesRng::from_seed(seed_prover.into());
            let mut rng_vr = AesRng::from_seed(seed_verifier.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_pr, mut generator_vr) = generators(&mut rng_pr, &mut rng_vr);
            let (output_pr, output_vr) = generate(&bits, &mut generator_pr, &mut generator_vr, &mut rng_pr, &mut rng_vr, false, true);
            let validation = validate(
                &output_pr,
                &output_vr,
                generator_vr.delta().into_inner(IS_VERIFIER),
            );
            prop_assert!(!validation);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn tampered_delta_fails(bits in proptest::collection::vec(any::<bool>(), 1..1000),
                                delta in any::<u128>(),
                                seed_prover in any::<u128>(),
                                seed_verifier in any::<u128>()) {
            let mut rng_pr = AesRng::from_seed(seed_prover.into());
            let mut rng_vr = AesRng::from_seed(seed_verifier.into());
            let bits: Vec<F2> = bits.into_iter().map(F2::from).collect();
            let (mut generator_pr, mut generator_vr) = generators(&mut rng_pr, &mut rng_vr);
            let (output_pr, output_vr) = generate(&bits, &mut generator_pr, &mut generator_vr, &mut rng_pr, &mut rng_vr, false, true);
            let validation = validate(&output_pr, &output_vr, U8x16::from(delta));
            // If all bits are 0, then `delta` never comes into play, so
            // validation "succeeds". Hence, only assert if this is not the case.
            if !bits.into_iter().all(|bit| bit == F2::ZERO) {
                prop_assert!(!validation);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn bitxor_works(nbits in 320..1000,
                        seed_prover in any::<u128>(),
                        seed_verifier in any::<u128>()) {
            let mut rng_a = AesRng::from_seed(seed_prover.into());
            let mut rng_b = AesRng::from_seed(seed_verifier.into());
            let bits1: Vec<_> = (0..nbits).map(|_| rng_a.r#gen::<F2>()).collect();
            let bits2: Vec<_> = (0..nbits).map(|_| rng_a.r#gen::<F2>()).collect();
            let (mut generator_a, mut generator_b) = generators(&mut rng_a, &mut rng_b);
            let (output_a, output_b) = generate(
                &bits1,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
                false,
                false,
            );
            let (output_c, output_d) = generate(
                &bits2,
                &mut generator_a,
                &mut generator_b,
                &mut rng_a,
                &mut rng_b,
                false,
                false,
            );
            // `results = (a ^ c, b ^ d)`
            let results: Vec<_> = output_a
                .iter()
                .zip(output_b.iter())
                .zip(output_c.iter().zip(output_d.iter()))
                .map(|((a, b), (c, d))| (*a ^ *c, *b ^ *d))
                .collect();
            // Test that `bitxor` works as intended.
            for (result, ((a, b), (c, d))) in results.iter().zip(
                output_a
                    .iter()
                    .zip(output_b.iter())
                    .zip(output_c.iter().zip(output_d.iter())),
            ) {
                assert_eq!(
                    result.0.bit().into_inner(IS_PROVER),
                    a.bit().into_inner(IS_PROVER) + c.bit().into_inner(IS_PROVER)
                );
                assert_eq!(
                    result.0.mac().into_inner(IS_PROVER),
                    a.mac().into_inner(IS_PROVER) ^ c.mac().into_inner(IS_PROVER)
                );
                assert_eq!(
                    result.1.key().into_inner(IS_VERIFIER),
                    b.key().into_inner(IS_VERIFIER) ^ d.key().into_inner(IS_VERIFIER)
                );
            }
        }
    }
}
