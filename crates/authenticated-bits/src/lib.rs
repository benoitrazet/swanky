use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use scuttlebut::Malicious;
use std::io::{Read, Write};
use swanky_party::{
    either::PartyEitherCopy, private::VerifierPrivateCopy, IsParty, Party, Prover, Verifier,
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
/// A type that represents the Party's part of the authentication bit
///
/// When `P = Prover`, this value is `ProverAuthBit`
/// When `P = Verifier`, this value is `VerifierAuthBit`
struct AuthBit<P: Party> {
    data: PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>,
}

/// A struct which contains multiple generated authentication bit
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
struct AuthBitGenerator<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> {
    /// A vector of authenticated bit.
    data: Vec<AuthBit<P>>,
    /// The verifier's global key.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party's sending OT
    ots: OTS,
    /// The party's receiving OT
    otr: OTR,
}

impl<
        P: Party,
        OTS: CorrelatedSender<Msg = U8x16> + Malicious,
        OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
    > AuthBitGenerator<P>
{
    /// Create a new `AuthBitGenerator` based on the type of
    /// the party. In the case of the `Verifier`, store the
    /// `delta` value.
    pub fn new<RNG>(delta: VerifierPrivateCopy<P, U8x16>, mut channel: C, mut rng: RNG) -> Self
    where
        RNG: CryptoRng + Rng,
    {
        AuthBitGenerator {
            data: vec![],
            delta: delta,
            ots: OTS::init(&mut channel, &mut rng)?,
            otr: OTR::init(&mut channel, &mut rng)?,
        }
    }
    // Generate `count` authenticated bits. These are stored in `output`.
    pub fn generate<C: Read + Write>(
        &mut self,
        channel: C,
        count: usize,
        output: &mut Vec<AuthBit<P>>,
    ) -> Result<(), AuthenticationBitError> {
        todo!()
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
