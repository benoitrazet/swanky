use super::crypto_primitives::{CHALL1_LENGTH, CHALL3_LENGTH};
use super::functionality::{decommit, VoleVerifier};
use super::{AsSecretBytes, RandomVole};
use crate::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
use crate::vole::functionality::{create_vole_prover, PartialDecommitment, VoleProver};
use eyre::{bail, Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use swanky_field_binary::{F128b, F2};

// This is a first attempt to connect the VOLE part to the circuit traverser.

impl RandomVole for VoleProver {
    type Decommitment = PartialDecommitment;

    type VoleChallenge = [u8; CHALL1_LENGTH];

    type VoleDecommitmentChallenge = [u8; CHALL3_LENGTH];

    fn create<Secret: AsSecretBytes>(
        extended_witness_length: usize,
        transcript: &mut Transcript,
        secret: &Secret,
        _rng: &mut (impl CryptoRng + RngCore),
    ) -> (Self, Self::VoleChallenge) {
        let mut statement_sig = [0u8; 16];
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);
        let vole = create_vole_prover(
            &statement_sig,
            secret,
            extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM,
        );
        let chall = vole.chall1;
        (vole, chall)
    }

    fn extract_vole_challenge(
        _transcript: &mut Transcript,
        _extended_witness_length: usize,
    ) -> Self::VoleChallenge {
        unimplemented!("not totally sure here. func only used on the verifier side")
    }

    fn count(&self) -> usize {
        self.u.len()
    }

    fn extended_witness_length(&self) -> usize {
        self.count() - REPETITION_PARAM * VOLE_SIZE_PARAM
    }

    fn witness_mask(&self) -> &[F2] {
        &self.u[0..self.extended_witness_length()]
    }

    fn aggregate_commitment_values(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let ell = self.extended_witness_length();
        self.u[ell..ell + REPETITION_PARAM * VOLE_SIZE_PARAM]
            .iter()
            .map(|f2| F128b::from(*f2))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    fn aggregate_commitment_masks(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let ell = self.extended_witness_length();
        self.v[ell..ell + REPETITION_PARAM * VOLE_SIZE_PARAM]
            .to_vec()
            .try_into()
            .unwrap()
    }

    fn vole_mask(&self, i: usize) -> Result<F128b> {
        if i < self.extended_witness_length() {
            Ok(self.v[i])
        } else {
            bail!(
                "vole mask index out of range: should be in [0, {}), but got {}",
                self.extended_witness_length(),
                i
            );
        }
    }
    fn extract_decommitment_challenge(
        _transcript: &mut Transcript,
    ) -> Self::VoleDecommitmentChallenge {
        unimplemented!("not totally sure here")
    }

    fn decommit(
        self,
        transcript: &mut Transcript,
    ) -> (Self::Decommitment, Self::VoleDecommitmentChallenge) {
        let decommitment_challenge = Self::extract_decommitment_challenge(transcript);
        (
            decommit(self, decommitment_challenge),
            decommitment_challenge,
        )
    }
}

// The functions in this implementation are the ones from `InsecureCommitments`
#[allow(unused)]
impl VoleVerifier {
    pub(crate) fn extended_witness_length(&self) -> usize {
        self.q.len() - REPETITION_PARAM * VOLE_SIZE_PARAM
    }

    pub(crate) fn verifier_key_array(&self) -> &F128b {
        &self.delta
    }

    pub(crate) fn witness_voles(&self) -> &[F128b] {
        let count = self.q.len();
        &self.q[0..count - REPETITION_PARAM * VOLE_SIZE_PARAM]
    }

    pub(crate) fn mask_voles(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        let count = self.q.len();
        self.q[count - REPETITION_PARAM * VOLE_SIZE_PARAM..count]
            .try_into()
            .unwrap()
    }
}
