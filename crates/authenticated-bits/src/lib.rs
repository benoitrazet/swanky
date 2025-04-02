use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::Malicious;
use std::io::{Read, Write};
use swanky_channel::Channel;
use swanky_party::{
    either::PartyEither, either::PartyEitherCopy, private::VerifierPrivateCopy, IsParty, Party,
    Prover, Verifier, WhichParty,
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
    /// Local key
    key: U8x16,
}
/// A type that represents the Party's part of the authenticated bit
///
/// When `P = Prover`, this value is `ProverAuthBit`
/// When `P = Verifier`, this value is `VerifierAuthBit`
struct AuthBit<P: Party> {
    data: PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>,
}

/// A struct which contains a single authenticated bit
impl<P: Party> AuthBit<P> {
    /// This outputs the key associated with the AuthBit
    pub fn key(&self, ev: IsParty<P, Verifier>) -> U8x16 {
        return self.data.verifier_into(ev).key;
    }
    /// Output the mac associated with the `AuthBit`
    pub fn mac(&self, ev: IsParty<P, Prover>) -> U8x16 {
        return self.data.prover_into(ev).mac;
    }
    // "Open" a single Authenticated bit.
    // This corresponds to the prover sending $(b, M)$ to the verifier, who checks
    // that $K = M xor b Delta$.
    pub fn open(
        &self,
        delta: VerifierPrivateCopy<P, U8x16>,
        channel: &mut Channel,
    ) -> Result<VerifierPrivateCopy<P, bool>, AuthenticationBitError> {
        // TODO: Can we get rid of this pattern match ?
        // So far I haven't been able to because each party needs a copy
        // of the channel.
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                // TODO: Change how bits are sent, this is extremely inefficent
                channel.write_bytes(&[self.data.prover_into(ev_pr).bit as u8]);
                // TODO: Potentially leave last bit in the mac for the
                // authenticated bit.
                channel.write_bytes(self.data.prover_into(ev_pr).mac.as_ref());
                Ok(VerifierPrivateCopy::empty(ev_pr))
            }
            WhichParty::Verifier(ev_vr) => {
                let mut bit_bytes = [0u8; 1];
                channel.read_bytes(&mut bit_bytes);
                let mut mac_bytes = [0u8; 16];
                channel.read_bytes(&mut mac_bytes);
                let mac = U8x16::from(mac_bytes);

                let key = self.data.verifier_into(ev_vr).key;

                let validation = if bit_bytes[0] == 1 {
                    key + delta.into_inner(ev_vr)
                } else {
                    key
                };
                Ok(VerifierPrivateCopy::new(validation == mac))
            }
        }
    }
}

/// XOR two authenticated bits. Linear operations on authenticated bits are "free"
/// (i.e. can be done locally).
impl<P: Party> std::ops::BitXor for AuthBit<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let pairs = self.data.zip(rhs.data);
        AuthBit {
            data: pairs.map(
                |(lhs, rhs)| ProverAuthBit {
                    mac: lhs.mac ^ rhs.mac,
                    bit: lhs.bit ^ rhs.bit,
                },
                |(lhs, rhs)| VerifierAuthBit {
                    key: lhs.key ^ rhs.key,
                },
            ),
        }
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
        mut channel: Channel,
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
        mut channel: Channel,
        count: usize,
        output: &mut Vec<AuthBit<P>>,
        mut rng: RNG,
    ) -> Result<(), ocelot::Error>
    where
        RNG: CryptoRng + Rng,
    {
        // TODO: Can we get rid of this pattern match ?
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                let bits = vec![rng.gen::<bool>(); count];
                let macs = self.ot.as_mut().prover_into(ev_pr).receive_correlated(
                    &mut channel,
                    &bits,
                    &mut rng,
                )?;
                output.extend(bits.into_iter().zip(macs).map(|(bit, mac)| AuthBit {
                    data: PartyEitherCopy::prover_new(ev_pr, ProverAuthBit { bit: bit, mac: mac }),
                }));

                Ok(())
            }
            WhichParty::Verifier(ev_vr) => {
                let delta = self.delta(ev_vr);
                let keys = self.ot.as_mut().verifier_into(ev_vr).send_correlated(
                    &mut channel,
                    &vec![delta; count],
                    &mut rng,
                )?;
                output.extend(keys.into_iter().map(|(key, _delta)| AuthBit {
                    data: PartyEitherCopy::verifier_new(ev_vr, VerifierAuthBit { key: key }),
                }));

                Ok(())
            }
        }
    }
    ///
    /// TODO: Possibly add the index of the bit to check
    pub fn open(
        &self,
        channel: &mut Channel,
    ) -> Result<VerifierPrivateCopy<P, bool>, AuthenticationBitError> {
        //TODO: Get rid of these unwraps
        let validations = self
            .data
            .iter()
            .map(|auth_bit| auth_bit.open(self.delta, channel).unwrap());
        match P::WHICH {
            WhichParty::Prover(ev_pr) => Ok(VerifierPrivateCopy::empty(ev_pr)),
            WhichParty::Verifier(ev_vr) => Ok(VerifierPrivateCopy::new(
                validations
                    // TODO: possibly return the index of the bit that failed if a
                    // failure happens
                    .reduce(|b1, b2| {
                        VerifierPrivateCopy::new(b1.into_inner(ev_vr) && b2.into_inner(ev_vr))
                    })
                    .is_some(),
            )),
        }
    }
    /// This outputs the verifier's Delta value.
    pub fn delta(&self, ev: IsParty<P, Verifier>) -> U8x16 {
        self.delta.into_inner(ev)
    }
}
