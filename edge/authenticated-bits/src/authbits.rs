//! Authenticated bits.
//!
//! See [`crate`] for a high-level description of authenticated bits. This
//! module provides the [`AuthBit`] type, which represents an authenticated bit,
//! alongside the [`AuthBitGenerator`] type, which provides a means for
//! generating a vector of [`AuthBit`]s.
//!
//! # Details
//!
//! To generate [`AuthBit`]s, the prover holds a vector of bits $`b_i`$ of
//! length $`n`$, and the verifier holds a long term key $`\Delta`$.
//!
//! The prover and verifier perform a correlated OT per bit so that the prover
//! receives $`M_i := K_i \oplus b_i \Delta`$ and the verifier receives $`K_i`$.
//! In other words:
//!
//! - If $`b_i = 1`$: the prover receives $`M_{i,0} := K_i \oplus \Delta`$.
//! - if $`b_i = 0`$: the prover receives $`M_{i,1} := K_i`$.
//!
//! The verifier receives both $`M_{i,0}`$ and $`M_{i,1} = K_i`$.
//!
//! To open an authenticated bit, the prover sends $`(b_i, M_i)`$ to the
//! verifier and the verifier checks that $`M_i := K_i \oplus b \Delta`$.
//!
//! # Example
//!
//! ```
//! # use rand::Rng;
//! # use swanky_authenticated_bits::authbits::{AuthBit, AuthBitGenerator};
//! # use swanky_field_binary::F2;
//! # use swanky_ot_alsz_kos::kos;
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
//!         let mut generator: AuthBitGenerator<_, kos::Sender, kos::Receiver> = AuthBitGenerator::new(c, &mut rng)?;
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
//!         let mut generator: AuthBitGenerator<_, kos::Sender, kos::Receiver> = AuthBitGenerator::new(c, &mut rng)?;
//!         generator.generate(PartyEitherCopy::verifier_new(IS_VERIFIER, count), &mut authbits, c, &mut rng)?;
//!         generator.open(&authbits, VerifierPrivate::new(&mut bits), c)?;
//!         Ok(bits)
//!     }
//! )?;
//! assert_eq!(bits_prover, bits_verifier);
//! # Ok(())
//! # }
//! ```

use rand::{CryptoRng, Rng};
use swanky_adversary::Malicious;
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::{F2, F2BitDeserializer, F2BitSerializer, F128b};
use swanky_ot_traits::{CorrelatedReceiver, CorrelatedSender};
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
#[derive(Debug, Default, Clone, Copy)]
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
#[derive(Debug, Default, Clone, Copy)]
struct VerifierAuthBit {
    /// Key authenticating the prover's MAC.
    key: U8x16,
}
/// An authenticated bit.
///
/// See [`crate::authbits`] for details.
#[derive(Default, Clone, Copy)]
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

/// XOR two authenticated bits with assignment. Linear operations on authenticated bits
/// are "free" (i.e. can be done locally).
impl<P: Party> std::ops::BitXorAssign for AuthBit<P> {
    fn bitxor_assign(&mut self, rhs: Self) {
        match P::WHICH {
            WhichParty::Prover(e) => {
                self.to_prover().into_inner(e).bit += rhs.to_prover().into_inner(e).bit;
                self.to_prover().into_inner(e).mac ^= rhs.to_prover().into_inner(e).mac;
            }

            WhichParty::Verifier(e) => {
                self.to_verifier().into_inner(e).key ^= rhs.to_verifier().into_inner(e).key;
            }
        }
    }
}

/// A type for generating [`AuthBit`]s.
pub struct AuthBitGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    /// The verifier's global $`\Delta`$.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party-specific correlated OT instantiation.
    ot: PartyEither<P, OTR, OTS>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthBitGenerator<P, OTS, OTR>
{
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
                ot: PartyEither::prover_new(e, OTR::init(channel, &mut rng)?),
            },
            WhichParty::Verifier(e) => AuthBitGenerator {
                delta: VerifierPrivateCopy::new(delta.into_inner(e)),
                ot: PartyEither::verifier_new(e, OTS::init(channel, &mut rng)?),
            },
        };
        Ok(result)
    }
    /// Generate a vector of authenticated of bits.
    ///
    /// - `bits_in`: The bits to authenticate. The prover specifies the bits themselves, and the verifier specifies the _number_ of bits.
    /// - `out`: Where the generated authenticated bits should be stored.
    /// - `channel`: The [`Channel`] to use.
    /// - `rng`: The random number generator to use.
    pub fn generate<RNG>(
        &mut self,
        bits_in: PartyEitherCopy<P, &[F2], usize>,
        out: &mut Vec<AuthBit<P>>,
        mut channel: &mut Channel,
        mut rng: RNG,
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
                    &mut rng,
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
                    &mut rng,
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
    /// returned to the verifier in the `outputs` vector.
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
                for _ in 0..authbits.len() {
                    bits_.push(bit_ser.read(channel.as_std_io())?);
                }
                let mut validation = true;
                for (ab, bit) in authbits.iter().zip(bits_.iter()) {
                    let mut mac_bytes = [0u8; 16];
                    channel.read_bytes(&mut mac_bytes)?;
                    let mac = U8x16::from(mac_bytes);

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
    use swanky_aes_rng::AesRng;
    use swanky_field::FiniteRing;
    use swanky_ot_alsz_kos::kos::{Receiver as KosReceiver, Sender as KosSender};
    use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier, either::PartyEitherCopy};

    /// Validates pairs of prover and verifier `AuthBit`s.
    fn validate(pr: &[AuthBit<Prover>], vr: &[AuthBit<Verifier>], delta: U8x16) -> bool {
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
        tamper_mac: bool,
        tamper_key: bool,
    ) -> (
        Vec<AuthBit<Prover>>,
        Vec<AuthBit<Verifier>>,
        AuthBitGenerator<Prover, KosSender, KosReceiver>,
        AuthBitGenerator<Verifier, KosSender, KosReceiver>,
    ) {
        let mut output_pr: Vec<AuthBit<Prover>> = vec![];
        let mut output_vr: Vec<AuthBit<Verifier>> = vec![];
        let (prover, verifier) = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();
                let bits = PartyEitherCopy::prover_new(IS_PROVER, bits_in);
                let mut generator: AuthBitGenerator<_, KosSender, KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(channel_pr, &mut rng)?;
                generator.generate::<&mut AesRng>(bits, &mut output_pr, channel_pr, &mut rng)?;
                if tamper_mac {
                    // Tamper the MAC of the first `AuthBit`.
                    output_pr[0] = AuthBit(PartyEitherCopy::prover_new(
                        IS_PROVER,
                        ProverAuthBit {
                            bit: output_pr[0].bit().into_inner(IS_PROVER),
                            mac: rng.r#gen(),
                        },
                    ));
                }
                generator.open(&output_pr, VerifierPrivate::empty(IS_PROVER), channel_pr)?;
                Ok(generator)
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let count = PartyEitherCopy::verifier_new(IS_VERIFIER, bits_in.len());
                let mut generator: AuthBitGenerator<_, KosSender, KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(channel_vr, &mut rng).unwrap();
                generator.generate::<&mut AesRng>(count, &mut output_vr, channel_vr, &mut rng)?;
                if tamper_key {
                    // Tamper the key of the first `AuthBit`.
                    output_vr[0] = AuthBit(PartyEitherCopy::verifier_new(
                        IS_VERIFIER,
                        VerifierAuthBit { key: rng.r#gen() },
                    ));
                }
                let mut output = vec![];
                let validation =
                    generator.open(&output_vr, VerifierPrivate::new(&mut output), channel_vr);
                // The generated bits should always be valid when no tampering happens.
                if !tamper_mac && !tamper_key {
                    assert!(validation.is_ok());
                } else {
                    assert!(validation.is_err());
                }
                Ok(generator)
            },
        )
        .unwrap();
        (output_pr, output_vr, prover, verifier)
    }

    #[test]
    fn xor_with_const_works() {
        let count = 1000;
        let mut rng = AesRng::new();
        let bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let public_bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let (output_pr, output_vr, prover, verifier) = generate(&bits, false, false);
        for ((authbit_pr, authbit_vr), public_bit) in output_pr
            .into_iter()
            .zip(output_vr.into_iter())
            .zip(public_bits.into_iter())
        {
            let new_authbit_pr = prover.xor_with_const(authbit_pr, public_bit);
            let new_authbit_vr = verifier.xor_with_const(authbit_vr, public_bit);
            // The new authenticated bits should still validate.
            let validation = validate(
                &[new_authbit_pr],
                &[new_authbit_vr],
                verifier.delta().into_inner(IS_VERIFIER),
            );
            assert!(validation);
            // The new authenticated bits should equal `bit ^ public_bit`.
            assert_eq!(
                new_authbit_pr.bit().into_inner(IS_PROVER),
                authbit_pr.bit().into_inner(IS_PROVER) + public_bit
            );
        }
    }

    #[test]
    // TODO: Turn this into a proptest
    fn honest_generation_works() {
        let count = 1000;
        let mut rng = AesRng::new();
        let bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let (output_pr, output_vr, _, verifier) = generate(&bits, false, false);
        let validation = validate(
            &output_pr,
            &output_vr,
            verifier.delta().into_inner(IS_VERIFIER),
        );
        assert!(validation);
    }

    #[test]
    // TODO: Turn this into a proptest
    fn tampered_mac_fails() {
        let count = 1000;
        let mut rng = AesRng::new();
        let bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let (output_pr, output_vr, _, verifier) = generate(&bits, true, false);
        let validation = validate(
            &output_pr,
            &output_vr,
            verifier.delta().into_inner(IS_VERIFIER),
        );
        assert!(!validation);
    }

    #[test]
    // TODO: Turn this into a proptest
    fn tampered_key_fails() {
        let count = 1000;
        let mut rng = AesRng::new();
        let bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let (output_pr, output_vr, _, verifier) = generate(&bits, false, true);
        let validation = validate(
            &output_pr,
            &output_vr,
            verifier.delta().into_inner(IS_VERIFIER),
        );
        assert!(!validation);
    }

    #[test]
    // TODO: Turn this into a proptest
    fn tampered_delta_fails() {
        let count = 1000;
        let mut rng = AesRng::new();
        let bits: Vec<F2> = (0..count).map(|_| rng.r#gen::<F2>()).collect();
        let (output_pr, output_vr, _, _) = generate(&bits, false, false);
        let validation = validate(&output_pr, &output_vr, rng.r#gen::<U8x16>());
        assert!(!validation);
    }
}
