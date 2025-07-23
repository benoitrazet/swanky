#![deny(missing_docs)]
//! Two-party function $`\mathcal{F}_{\mathsf{eq}}`$ that allows parties to check if their inputs are equal in an oblivious manner.
//!
//! In the literature this is typically handled by an ideal functionality $`\mathcal{F}_{\mathsf{eq}}`$ which receives
//! the inputs and return the valuation of the equality check.
//!
//! In practice,
//! 1. Party A and Party B use the same hash function to locally hash their inputs, we
//!    use SHA256 in our implementation. Each party may update their local hash with as
//!    many inputs as they would like: by doing so we batch calls to $`\mathcal{F}_{\mathsf{eq}}`$ so that any one
//!    equality triggers a failure. We do not care about logging which input caused the
//!    failure because any failure is an effect of cheating behavior and the protocol should
//!    terminate.
//! 2. Party A commits to their input by salting it and sends the commitment to Party B.
//!    In our code, SHA256 is updated with a random salt and the salted value is sent over
//!    to Party B.
//! 3. Party B sends their hashed value after receiving A's commitment.
//! 4. Party A may abort at this point. If they behave honestly, they open their commitment and
//!    check the equality. In our code, we decommit by sending the salt to Party B.
//! 5. Party B receives the decommited value and checks the equality (similarly to Party A).
//!
//! This functionality is commonly used in several cryptographic protocols including Garbled Circuits.
//!
//! Notes:
//! 1. Party A can abort after receiving Party B's value.
//! 2. The bashed hashing does not separate values. Meaning that:
//!    $`\mathcal{F}_{\mathsf{eq}}(0x1234 || 0x5678)`$ is the same as $`\mathcal{F}_{\mathsf{eq}}(0x12 || 0x345678)`$.
//!    This is not a concern for our use cases.

use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_party::{Party, WhichParty, private::ProverPrivate};

/// The equality functionality.
///
/// See [`crate`] for details.
pub struct EqualityFunctionality<P: Party> {
    hash: Sha256,
    commitment_salt: ProverPrivate<P, [u8; 32]>,
}

impl<P: Party> EqualityFunctionality<P> {
    /// Create a new [`EqualityFunctionality`].
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
    /// Add a sequence of bytes to the sequence of values to perform equality on.
    pub fn input(&mut self, value: &[u8]) {
        self.hash.update(value);
    }
    /// Runs the equality check on all the inputs provided in [`input(&mut self, value: &[u8])`].
    pub fn finalize(mut self, channel: &mut Channel) -> eyre::Result<()> {
        match P::WHICH {
            WhichParty::Prover(e) => {
                // Sender computes the commitment as H(H(value)||salt)
                let mut salted_hash = Sha256::new();
                salted_hash.update(self.hash.finalize());
                salted_hash.update(self.commitment_salt.as_ref().into_inner(e));
                // Sender sends commitment
                let sender_commitment = salted_hash.finalize();
                channel.write_bytes(sender_commitment.as_slice())?;
                // Sender receives receiver_hash
                let mut receiver_hash = [0u8; 32];
                channel.read_bytes(&mut receiver_hash)?;
                // Sender sends the commitment salt as a way to decommit. The sender
                // can abhort and skip this step and this protocol allows that.
                channel.write_bytes(self.commitment_salt.as_ref().into_inner(e))?;
                // The Sender salts the Receiver's value
                let mut receiver_salted = Sha256::new();
                receiver_salted.update(receiver_hash);
                receiver_salted.update(self.commitment_salt.as_ref().into_inner(e));
                // The Sender compares the salted values
                if sender_commitment != receiver_salted.finalize() {
                    Err(eyre::Error::msg("Validation check failed"))
                } else {
                    Ok(())
                }
            }
            WhichParty::Verifier(_e) => {
                let mut sender_commitment = [0u8; 32];
                let hash_receiver = self.hash.finalize();
                // Receiver receives commitment
                channel.read_bytes(&mut sender_commitment)?;
                // Receiver sends hash
                channel.write_bytes(hash_receiver.as_slice())?;
                // Receiver receives decommitment
                let mut sender_salt = [0u8; 32];
                channel.read_bytes(&mut sender_salt)?;
                //The Receiver salts its value
                let mut receiver_salted = Sha256::new();
                receiver_salted.update(hash_receiver);
                receiver_salted.update(sender_salt);
                //The Receiver compares the salted valuesS
                if sender_commitment != *receiver_salted.finalize() {
                    Err(eyre::Error::msg("Validation check failed"))
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::TestRunner;
    use swanky_aes_rng::AesRng;
    use swanky_party::{Prover, Verifier};

    fn check_equality(input_pr: &[u8], input_vr: &[u8]) -> eyre::Result<()> {
        swanky_channel::local::local_channel_pair(
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
        Ok(())
    }

    proptest! {
        #[test]
        fn same_inputs_work(input in any::<[u8; 32]>()) {
            let res = check_equality(&input, &input);
            assert!(res.is_ok());
        }
    }

    #[test]
    fn different_inputs_fail() {
        let mut runner = TestRunner::default();
        runner
            .run(
                &(any::<[u8; 32]>(), any::<[u8; 32]>()),
                |(input_pr, input_vr)| {
                    let res = check_equality(&input_pr, &input_vr);
                    assert!(res.is_err());
                    Ok(())
                },
            )
            .unwrap();
    }
}
