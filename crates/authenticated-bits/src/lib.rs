use std::io::{Read, Write};
use swanky_party::{
    either::PartyEitherCopy, private::VerifierPrivateCopy, IsParty, Party, Prover, Verifier,
    WhichParty,
};
use vectoreyes::U8x16;

/// TODO: Figure out better Error handling
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthenticationBitError;
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
    pub mac: U8x16,
    /// Bit value
    pub bit: bool,
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
type AuthBit<P> = PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>;
/// A struct which contains multiple generated authentication bit
///
/// When `P = Verifier`, this struct also stores the verifier's
/// global key `delta`.
struct AuthBitGenerator<P: Party> {
    /// A vector of authenticated bit.
    data: Vec<AuthBit<P>>,
    /// The verifier's global key.
    delta: VerifierPrivateCopy<P, U8x16>,
}

impl<P: Party> AuthBitGenerator<P> {
    /// Create a new `AuthBitGenerator` based on the type of
    /// the party. In the case of the `Verifier`, store the
    /// `delta` value.
    pub fn new(delta: VerifierPrivateCopy<P, U8x16>) -> Self {
        AuthBitGenerator {
            data: vec![],
            delta: delta,
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
    // XOR two authenticated bits. Linear operations on authenticated bits are "free"
    // (i.e. can be done locally).
    pub fn xor(&self, a: AuthBit<P>, b: AuthBit<P>) -> AuthBit<P> {
        match P::WHICH {
            WhichParty::Prover(pr) => {
                return PartyEitherCopy::prover_new(
                    pr,
                    ProverAuthBit {
                        mac: a.prover_into(pr).mac ^ b.prover_into(pr).mac,
                        bit: a.prover_into(pr).bit ^ b.prover_into(pr).bit,
                    },
                )
            }
            WhichParty::Verifier(ev) => PartyEitherCopy::verifier_new(
                ev,
                VerifierAuthBit {
                    key: a.verifier_into(ev).key ^ b.verifier_into(ev).key,
                },
            ),
        }
    }
    /// This outputs the verifier's Delta value.
    pub fn delta(&self, ev: IsParty<P, Verifier>) -> U8x16 {
        return self.delta.verifier_into(ev).into_inner(ev);
    }
    /// This outputs the key associated with the AuthBit
    pub fn key(&self, bit: &AuthBit<P>, ev: IsParty<P, Verifier>) -> U8x16 {
        return bit.verifier_into(ev).key;
    }
    /// Output the mac associated with the `AuthBit`
    pub fn mac(&self, bit: &AuthBit<P>, ev: IsParty<P, Prover>) -> U8x16 {
        return bit.prover_into(ev).mac;
    }
}
