#![deny(missing_docs)]
//! Two-party function F_eq that allows parties to check if their inputs are equal. This functionality is commonly used in several cryptographic protocols including Garbled Circuits.
// This name isn't great, I'm open to improvements.

use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_party::{Party, Prover, Verifier, WhichParty, private::ProverPrivate};

use eyre;
use rand::{CryptoRng, Rng};

struct EqualityFunctionality<P: Party> {
    hash: Sha256,
    commitment_salt: ProverPrivate<P, [u8; 32]>,
}

impl<P: Party> EqualityFunctionality<P> {
    /// Create a new [`EqualityFunctionality`].
    ///
    /// The verifier's generates the hash function's key `hash_key`, both parties
    /// setup their local hash functions using that key, and the prover samples a
    /// salt `commitment_salt` at random that they will later use to commit to their
    /// value.
    pub fn new<RNG>(mut rng: RNG) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        let result = match P::WHICH {
            WhichParty::Prover(e) => {}
            WhichParty::Verifier(e) => {}
        };
        todo!()
    }
    // Add `value` to the running hash.
    pub fn input(&mut self, value: &[u8]) -> () {
        match P::WHICH {
            WhichParty::Prover(e) => {}
            WhichParty::Verifier(e) => {}
        }
        todo!()
    }
    // Run the protocol:
    // If `P = Prover` send the committed hashed value over, receive the result, decommit, and do the equality.
    // If `P = Verifier` receive the commitment, send the hashed value over, receive the decommitment, and do the equality.
    pub fn finalize(self, channel: &mut Channel) -> eyre::Result<()> {
        match P::WHICH {
            WhichParty::Prover(e) => {}
            WhichParty::Verifier(e) => {}
        }
        todo!()
    }
}
