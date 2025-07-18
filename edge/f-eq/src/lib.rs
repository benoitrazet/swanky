#![deny(missing_docs)]
//! Two-party function F_eq that allows parties to check if their inputs are equal. This functionality is commonly used in several cryptographic protocols including Garbled Circuits.
// This name isn't great, I'm open to improvements.

use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_party::{Party, WhichParty, private::ProverPrivate};

use rand::{CryptoRng, Rng};

/// A struct which stores the hash function and salt used
/// in the F_eq protocol.
pub struct EqualityFunctionality<P: Party> {
    hash: Sha256,
    commitment_salt: ProverPrivate<P, [u8; 32]>,
}

impl<P: Party> EqualityFunctionality<P> {
    /// Create a new [`EqualityFunctionality`].
    ///
    /// The parties initialize their hash functions, and the sender samples a
    /// salt `commitment_salt` at random that they will later use to commit to their
    /// value.
    pub fn new<RNG>(mut rng: RNG) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        let result = match P::WHICH {
            WhichParty::Prover(_e) => EqualityFunctionality {
                hash: Sha256::new(),
                commitment_salt: ProverPrivate::new(rng.r#gen()),
            },
            WhichParty::Verifier(e) => EqualityFunctionality {
                hash: Sha256::new(),
                commitment_salt: ProverPrivate::empty(e),
            },
        };
        Ok(result)
    }
    /// Add `value` to the running hash.
    pub fn input(&mut self, value: &[u8]) {
        match P::WHICH {
            WhichParty::Prover(e) => {
                // We compute the commitment as H(H(value)||salt)
                let hash_sender = Sha256::digest(value);
                self.hash.update(hash_sender);
                self.hash
                    .update(self.commitment_salt.as_mut().into_inner(e));
            }
            WhichParty::Verifier(_e) => {
                self.hash.update(value);
            }
        }
    }
    /// Runs the protocol and checks the equality of the two hash values:
    /// If `P = Prover` send the committed hashed value over, receive the result, decommit, and do the equality.
    /// If `P = Verifier` receive the commitment, send the hashed value over, receive the decommitment, and do the equality.
    pub fn finalize(&mut self, channel: &mut Channel) -> eyre::Result<bool> {
        match P::WHICH {
            WhichParty::Prover(e) => {
                // Sender send commitment
                let sender_commitment = self.hash.clone().finalize();
                channel.write_bytes(sender_commitment.as_slice())?;
                // Sender receives h_verifier
                let mut receiver_hash = vec![0u8; 32];
                channel.read_bytes(&mut receiver_hash)?;
                // Sender sends the commitment salt as a way to decommit. The prover
                // can abhort and skip this step and this protocol allows that.
                channel.write_bytes(self.commitment_salt.as_mut().into_inner(e))?;
                // The Sender salts the Receiver's value
                let mut receriver_salted = Sha256::new();
                receriver_salted.update(receiver_hash);
                receriver_salted.update(self.commitment_salt.as_mut().into_inner(e));
                // The Sender compares the salted values
                Ok(sender_commitment == receriver_salted.finalize())
            }
            WhichParty::Verifier(_e) => {
                // Verifier receives commitment
                let mut sender_commitment = vec![0u8; 32];
                channel.read_bytes(&mut sender_commitment)?;
                // Receiver sends hash
                channel.write_bytes(self.hash.clone().finalize().as_slice())?;
                // Receiver receives decommitment
                let mut sender_salt = vec![0u8; 32];
                channel.read_bytes(&mut sender_salt)?;
                //The Receiver salts its value
                let mut receriver_salted = Sha256::new();
                receriver_salted.update(self.hash.clone().finalize());
                receriver_salted.update(sender_salt);
                //The Receiver compares the salted valuesS
                Ok(receriver_salted.finalize().as_slice() == sender_commitment)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_aes_rng::AesRng;
    use swanky_party::{Prover, Verifier};

    fn check_equality(input_pr: &[u8], input_vr: &[u8]) -> eyre::Result<(bool, bool)> {
        let (res_pr, res_vr) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::new();
                let mut f_eq = EqualityFunctionality::<Prover>::new(&mut rng)?;
                f_eq.input(input_pr);
                f_eq.finalize(c)
            },
            |c| {
                let mut rng = AesRng::new();
                let mut f_eq = EqualityFunctionality::<Verifier>::new(&mut rng)?;
                f_eq.input(input_vr);
                f_eq.finalize(c)
            },
        )?;
        Ok((res_pr, res_vr))
    }
    #[test]
    //TODO: turn to proptest
    fn same_inputs_work() {
        let mut rng = AesRng::new();
        let input: [u8; 32] = rng.r#gen();
        let res = check_equality(&input, &input).unwrap();
        assert_eq!(res.0, res.1);
        assert!(res.0);
    }
    #[test]
    //TODO: turn to proptest
    fn different_inputs_work() {
        let mut rng = AesRng::new();
        let input_pr: [u8; 32] = rng.r#gen();
        let input_vr: [u8; 32] = rng.r#gen();
        let res = check_equality(&input_pr, &input_vr).unwrap();
        assert_eq!(res.0, res.1);
        assert!(!res.0);
    }
}
