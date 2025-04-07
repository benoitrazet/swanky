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
    /// Local key
    key: U8x16,
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
                let bits = vec![rng.r#gen::<bool>(); count];
                let macs = self.ot.as_mut().prover_into(ev_pr).receive_correlated(
                    &mut channel,
                    &bits,
                    &mut rng,
                )?;
                output.extend(bits.into_iter().zip(macs).map(|(bit, mac)| {
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
                output.extend(keys.into_iter().map(|(key, _delta)| {
                    AuthBit(PartyEitherCopy::verifier_new(
                        ev_vr,
                        VerifierAuthBit { key: key },
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
                self.data.iter().map(
                    |ab|                    // TODO: Change how bits are sent, this is extremely inefficent
                    {channel.write_bytes(&[ab.prover_bit().into_inner(ev_pr) as u8]);
                    // TODO: Potentially leave last bit in the mac for the
                    // authenticated bit.
                    channel.write_bytes(ab.prover_mac().into_inner(ev_pr).as_ref());},
                );
                Ok(VerifierPrivateCopy::empty(ev_pr))
            }
            WhichParty::Verifier(ev_vr) => {
                let validations = self.data.iter().map(|ab| {
                    let mut bit_bytes = [0u8; 1];
                    channel.read_bytes(&mut bit_bytes);
                    let mut mac_bytes = [0u8; 16];
                    channel.read_bytes(&mut mac_bytes);
                    let mac = U8x16::from(mac_bytes);

                    let key = ab.verifier_key().into_inner(ev_vr);

                    if bit_bytes[0] == 1 {
                        mac == key + self.delta().into_inner(ev_vr)
                    } else {
                        mac == key
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
