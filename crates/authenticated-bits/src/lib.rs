use itertools::Itertools;
use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Malicious};
use std::io::{Read, Write};
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
}

// XOR two authenticated bits. Linear operations on authenticated bits are "free"
// (i.e. can be done locally).
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
    /// The party's receiving OT
    otr: OTR,
    /// The party's sender OT
    ots: OTS,
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
    pub fn new<C, RNG>(delta: VerifierPrivateCopy<P, U8x16>, mut channel: C, mut rng: RNG) -> Self
    where
        RNG: CryptoRng + Rng,
        C: AbstractChannel,
    {
        AuthBitGenerator {
            data: vec![],
            delta: delta,
            otr: OTR::init(&mut channel, &mut rng).unwrap(),
            ots: OTS::init(&mut channel, &mut rng).unwrap(),
        }
    }
    // Generate `count` authenticated bits. These are stored in `output`.
    pub fn generate<C, RNG>(
        &mut self,
        mut channel: C,
        count: usize,
        output: &mut Vec<AuthBit<P>>,
        mut rng: RNG,
    ) -> Result<(), ocelot::Error>
    where
        RNG: CryptoRng + Rng,
        C: AbstractChannel,
    {
        match P::WHICH {
            WhichParty::Prover(ev_pr) => {
                let bits = vec![rng.gen::<bool>(); count];
                let macs = self
                    .otr
                    .receive_correlated(&mut channel, &bits, &mut rng)
                    .unwrap();
                for (i, (bit, mac)) in bits.into_iter().zip(macs).enumerate() {
                    output[i] = AuthBit {
                        data: PartyEitherCopy::prover_new(
                            ev_pr,
                            ProverAuthBit { bit: bit, mac: mac },
                        ),
                    };
                }
                Ok(())
            }
            WhichParty::Verifier(ev_vr) => {
                let keys = self.ots.send_correlated(
                    &mut channel,
                    &vec![self.delta(ev_vr); count],
                    &mut rng,
                )?;
                for (i, key) in keys.into_iter().enumerate() {
                    output[i] = AuthBit {
                        data: PartyEitherCopy::verifier_new(ev_vr, VerifierAuthBit { key: key.0 }),
                    };
                }
                Ok(())
            }
        }
    }
    // "Open" a bit.
    // This corresponds to the prover sending $(b, M)$ to the verifier, who checks
    // that $K = M xor b Delta$.
    pub fn open<C: Read + Write>(
        &self,
        channel: C,
        bit: AuthBit<P>,
    ) -> Result<(), AuthenticationBitError> {
        todo!()
    }
    /// This outputs the verifier's Delta value.
    pub fn delta(&self, ev: IsParty<P, Verifier>) -> U8x16 {
        self.delta.into_inner(ev)
    }
}
