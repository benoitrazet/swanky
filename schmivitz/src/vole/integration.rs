use super::crypto_primitives::{CHALL1_LENGTH, CHALL3_LENGTH};
use super::functionality::{decommit, VoleVerifier};
use super::{AsSecretBytes, Chall3, RandomVoleP, RandomVoleV};
use crate::parameters::{REPETITION_PARAM, SECURITY_PARAM, VOLE_SIZE_PARAM};
use crate::vole::functionality::{
    create_vole_prover, create_vole_verifier, PartialDecommitment, VoleProver,
};
use eyre::{bail, Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use swanky_field_binary::{F128b, F2};

// This is a first attempt to connect the VOLE part to the circuit traverser.

impl RandomVoleP for VoleProver {
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

    fn decommit(self, challenge: &[u8; SECURITY_PARAM / 8]) -> Self::Decommitment {
        decommit(self, challenge)
    }
}

impl RandomVoleV for VoleVerifier {
    type Decommitment = PartialDecommitment;

    fn reconstruct(
        decom: &Self::Decommitment,
        chall3: &Chall3,
        transcript: &mut Transcript,
    ) -> Self {
        let mut statement_sig = [0u8; 32];
        transcript.challenge_bytes(b"statement signature", &mut statement_sig);

        create_vole_verifier(&statement_sig, decom, chall3)
    }

    fn extended_witness_length(&self) -> usize {
        self.l
    }

    fn verifier_key_array(&self) -> &[swanky_field_binary::F8b; REPETITION_PARAM] {
        todo!()
    }

    fn verifier_key(&self) -> F128b {
        todo!()
    }

    fn witness_voles(&self) -> &[[swanky_field_binary::F8b; REPETITION_PARAM]] {
        todo!()
    }

    fn mask_voles(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        todo!()
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
