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
            WhichParty::Prover(e) => EqualityFunctionality {
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
    // Add `value` to the running hash.
    pub fn input(&mut self, value: &[u8]) -> () {
        match P::WHICH {
            WhichParty::Prover(e) => {
                // We compute the commitment as H(H(value)||salt)
                let hash_prover = Sha256::digest(value);
                self.hash.update(hash_prover);
                self.hash
                    .update(self.commitment_salt.as_mut().into_inner(e));
            }
            WhichParty::Verifier(e) => {
                self.hash.update(value);
            }
        }
    }
    // Run the protocol:
    // If `P = Prover` send the committed hashed value over, receive the result, decommit, and do the equality.
    // If `P = Verifier` receive the commitment, send the hashed value over, receive the decommitment, and do the equality.
    pub fn finalize(&mut self, channel: &mut Channel) -> eyre::Result<bool> {
        match P::WHICH {
            WhichParty::Prover(e) => {
                // Prover send commitment
                let prover_commitment = self.hash.clone().finalize();
                let _ = channel.write_bytes(prover_commitment.as_slice())?;
                // Prover receives h_verifier
                let mut verifier_hash = vec![0u8; 32];
                channel.read_bytes(&mut verifier_hash)?;
                // Prover sends the commitment salt as a way to decommit. The prover
                // can abhort and skip this step and this protocol allows that.
                let _ = channel.write_bytes(self.commitment_salt.as_mut().into_inner(e))?;
                // The Prover salts the Verifier's value
                let mut verifier_salted = Sha256::new();
                verifier_salted.update(verifier_hash);
                verifier_salted.update(self.commitment_salt.as_mut().into_inner(e));
                // The Prover compares the salted values
                return Ok(prover_commitment == verifier_salted.finalize());
            }
            WhichParty::Verifier(e) => {
                // Verifier receives commitment
                let mut prover_com = vec![0u8; 32];
                channel.read_bytes(&mut prover_com)?;
                // Verifier sends hash
                let _ = channel.write_bytes(self.hash.clone().finalize().as_slice())?;
                // Verifier receives decommitment
                let mut prover_salt = vec![0u8; 32];
                channel.read_bytes(&mut prover_salt)?;
                //The Verifier salts its value
                let mut verifier_salted = Sha256::new();
                verifier_salted.update(self.hash.clone().finalize());
                verifier_salted.update(prover_salt);
                //The Verifier compares the salted valuesS
                return Ok(verifier_salted.finalize().as_slice() == prover_com);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_aes_rng::AesRng;

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
    fn same_inputs_work() {
        let mut rng = AesRng::new();
        let input: [u8; 32] = rng.r#gen();
        let res = check_equality(&input, &input).unwrap();
        assert_eq!(res.0, res.1);
        assert_eq!(res.0, true);
    }
    #[test]
    fn different_inputs_work() {
        let mut rng = AesRng::new();
        let input_pr: [u8; 32] = rng.r#gen();
        let input_vr: [u8; 32] = rng.r#gen();
        let res = check_equality(&input_pr, &input_vr).unwrap();
        assert_eq!(res.0, res.1);
        assert_eq!(res.0, false);
    }
}
