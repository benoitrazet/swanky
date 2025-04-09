use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::Malicious;
use swanky_channel::Channel;
use swanky_party::{
    IsParty, Party, Prover, Verifier, WhichParty,
    either::PartyEither,
    either::PartyEitherCopy,
    private::{ProverPrivateCopy, VerifierPrivateCopy},
};
use vectoreyes::U8x16;
/// TODO: Figure out better Error handling
#[derive(Clone, Copy, Debug, Default)]
struct AuthenticationBitError;
impl std::fmt::Display for AuthenticationBitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AuthenticationBitError {}

/// The Prover's part of the authentication bit
///
/// The Prover holds a bit that they wish to
/// authenticate and receive a MAC which corresponds
/// to that authentication.
#[derive(Debug, Default, Clone, Copy)]
struct ProverAuthBit {
    /// Mac authenticating the bit
    mac: U8x16,
    /// Bit value
    bit: bool,
}
/// The Verifier's part of the authentication bit
///
/// The Verifier holds a local `key` per bit
/// that authenticates the bit and verifies the
/// integrity of the provers MAC.
#[derive(Debug, Default, Clone, Copy)]
struct VerifierAuthBit {
    /// Key from OT
    key: U8x16,
    /// Mac from OT
    mac: U8x16,
}
/// A type that represents the Party's part of the authenticated bit
///
/// When `P = Prover`, this value is `ProverAuthBit`
/// When `P = Verifier`, this value is `VerifierAuthBit`
struct AuthBit<P: Party>(PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>);

/// A struct which contains a single authenticated bit
impl<P: Party> AuthBit<P> {
    /// Retrieve the prover's `ProverAuthBit` from the  `PartyEitherCopy`
    pub fn prover_into(&self) -> ProverPrivateCopy<P, ProverAuthBit> {
        self.0.into_privates().0
    }
    /// Retrieve the verifier's `VerifierAuthBit` from the  `VerifierPrivateCopy`
    pub fn verifier_into(&self) -> VerifierPrivateCopy<P, VerifierAuthBit> {
        self.0.into_privates().1
    }
    /// This outputs the key associated with the AuthBit
    pub fn verifier_key(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.verifier_into().map(|vab| vab.key)
    }
    /// Output the mac associated with the `AuthBit`
    pub fn verifier_mac(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.verifier_into().map(|vab| vab.mac)
    }
    /// Output the mac associated with the `AuthBit`
    pub fn prover_mac(&self) -> ProverPrivateCopy<P, U8x16> {
        self.prover_into().map(|vab| vab.mac)
    }
    /// Output the mac associated with the `AuthBit`
    pub fn prover_bit(&self) -> ProverPrivateCopy<P, bool> {
        self.prover_into().map(|vab| vab.bit)
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
                bit: lhs.bit ^ rhs.bit,
            },
            |(lhs, rhs)| VerifierAuthBit {
                key: lhs.key ^ rhs.key,
                mac: lhs.mac ^ rhs.mac,
            },
        ))
    }
}

/// A struct which contains multiple generated authentication bit
///
/// When `P = Verifier`, this struct also stores the verifier's
/// global key `delta`.
struct AuthBitGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    /// A vector of authenticated bit.
    data: Vec<AuthBit<P>>,
    /// The verifier's global key.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party's OT
    ot: PartyEither<P, OTR, OTS>,
}

/// A struct which contains multiple generated authentication bit
impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthBitGenerator<P, OTS, OTR>
{
    /// Create a new `AuthBitGenerator` based on the type of
    /// the party. In the case of the `Verifier`, store the
    /// `delta` value.
    pub fn new<C, RNG>(
        delta: VerifierPrivateCopy<P, U8x16>,
        mut channel: &mut Channel,
        mut rng: RNG,
    ) -> Self
    where
        RNG: CryptoRng + Rng,
    {
        AuthBitGenerator {
            data: vec![],
            delta: delta,
            ot: match P::WHICH {
                WhichParty::Prover(ev_pr) => {
                    PartyEither::prover_new(ev_pr, OTR::init(&mut channel, &mut rng).unwrap())
                }
                WhichParty::Verifier(ev_vr) => {
                    PartyEither::verifier_new(ev_vr, OTS::init(&mut channel, &mut rng).unwrap())
                }
            },
        }
    }
    /// Generate `count` authenticated bits. These are stored in `output`.
    ///
    /// TODO: Possibly allow the user to specify the bits they would like
    /// authenticated instead of always generate them at random
    pub fn generate<C, RNG>(
        &mut self,
        mut channel: &mut Channel,
        count: usize,
        mut rng: RNG,
    ) -> Result<(), ocelot::Error>
    where
        RNG: CryptoRng + Rng,
    {
        // TODO: Can we get rid of this pattern match ?
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                let bits = vec![rng.r#gen::<bool>(); count];
                let macs = self.ot.as_mut().prover_into(ev_pr).receive_correlated(
                    &mut channel,
                    &bits,
                    &mut rng,
                )?;
                self.data
                    .extend(bits.into_iter().zip(macs).map(|(bit, mac)| {
                        AuthBit(PartyEitherCopy::prover_new(
                            ev_pr,
                            ProverAuthBit { bit: bit, mac: mac },
                        ))
                    }));

                Ok(())
            }
            WhichParty::Verifier(ev_vr) => {
                let delta = self.delta().into_inner(ev_vr);
                let keys = self.ot.as_mut().verifier_into(ev_vr).send_correlated(
                    &mut channel,
                    &vec![delta; count],
                    &mut rng,
                )?;
                self.data.extend(keys.into_iter().map(|(key, mac)| {
                    AuthBit(PartyEitherCopy::verifier_new(
                        ev_vr,
                        VerifierAuthBit { key: key, mac: mac },
                    ))
                }));

                Ok(())
            }
        }
    }
    /// "Open" a all authenticated bits.
    ///
    /// This corresponds to the prover sending $(b, M)$ to the verifier, who checks
    /// that $K = M xor b Delta$.
    pub fn open(
        &self,
        channel: &mut Channel,
    ) -> Result<VerifierPrivateCopy<P, bool>, AuthenticationBitError> {
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                let _ = self.data.iter().map(
                    |ab|                    // TODO: Change how bits are sent, this is extremely inefficent
                    {let _ = channel.write_bytes(&[ab.prover_bit().into_inner(ev_pr) as u8]);
                    // TODO: Potentially leave last bit in the mac for the
                    // authenticated bit.
                    let _ = channel.write_bytes(ab.prover_mac().into_inner(ev_pr).as_ref());},
                );
                Ok(VerifierPrivateCopy::empty(ev_pr))
            }
            WhichParty::Verifier(ev_vr) => {
                let validations = self.data.iter().map(|ab| {
                    let mut bit_bytes = [0u8; 1];
                    let _ = channel.read_bytes(&mut bit_bytes);
                    let mut mac_bytes = [0u8; 16];
                    let _ = channel.read_bytes(&mut mac_bytes);
                    let mac = U8x16::from(mac_bytes);

                    mac == if bit_bytes[0] == 1 {
                        ab.verifier_mac().into_inner(ev_vr)
                    } else {
                        ab.verifier_key().into_inner(ev_vr)
                    }
                });

                Ok(VerifierPrivateCopy::new(
                    validations
                        // TODO: possibly return the index of the bit that failed if a
                        // failure happens
                        .reduce(|b1, b2| b1 && b2)
                        .is_some(),
                ))
            }
        }
    }
    /// This outputs the verifier's Delta value.
    pub fn delta(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthBitGenerator;
    use proptest::prelude::*;
    // use rand::Rng;
    use ocelot::ot;
    use swanky_aes_rng::AesRng;
    use swanky_channel::Channel;
    use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier, private::VerifierPrivateCopy};
    pub fn authenticate_in_clear(pr: Vec<AuthBit<Prover>>, vr: Vec<AuthBit<Verifier>>) -> bool {
        pr.iter()
            .zip(vr)
            .map(|(ab_pr, ab_vr)| {
                ab_pr.prover_mac().into_inner(IS_PROVER)
                    == (if ab_pr.prover_bit().into_inner(IS_PROVER) {
                        ab_vr.verifier_mac().into_inner(IS_VERIFIER)
                    } else {
                        ab_vr.verifier_key().into_inner(IS_VERIFIER)
                    })
            })
            .reduce(|b1, b2| b1 && b2)
            .unwrap()
    }
    // proptest! {
    #[test]
    fn test_add() {
        let count = 1;
        let mut output_pr: Vec<AuthBit<Prover>> = vec![];
        let mut output_vr: Vec<AuthBit<Verifier>> = vec![];
        let mut rng = AesRng::new();

        let mut validation: bool = false;
        let _ = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();

                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<Channel, &mut AesRng>(
                        VerifierPrivateCopy::empty(IS_PROVER),
                        channel_pr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<Channel, &mut AesRng>(channel_pr, count, &mut rng);
                let _ = auth_bits.open(channel_pr);
                output_pr = auth_bits.data;

                Ok(())
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let delta = rng.r#gen::<U8x16>();
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<Channel, &mut AesRng>(
                        VerifierPrivateCopy::new(delta),
                        channel_vr,
                        &mut rng,
                    );
                let _ = auth_bits.generate::<Channel, &mut AesRng>(channel_vr, count, &mut rng);
                validation = auth_bits.open(channel_vr).unwrap().into_inner(IS_VERIFIER);
                output_vr = auth_bits.data;
                Ok(())
            },
        )
        .unwrap();
        let validation_clear = authenticate_in_clear(output_pr, output_vr);
        assert!(validation);
        assert_eq!(validation, validation_clear);
    }
    // }
}
