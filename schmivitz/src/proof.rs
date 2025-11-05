//! General-purpose VOLE-in-the-head proof.
//!
//! Much of the documentation refers to notation in "the paper"; this is referencing
//! Baum et al.[^vole].
//!
//! [^vole]: Carsten Baum, Lennart Braun, Cyprien Delpech de Saint Guilhem, Michael Klooß,
//! Emmanuela Orsini, Lawrence Roy, and Peter Scholl. [Publicly Verifiable Zero-Knowledge and
//! Post-Quantum Signatures from VOLE-in-the-head](https://eprint.iacr.org/2023/996). 2023.
//!
use eyre::{bail, Result};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use rayon::iter::*;
use std::{iter::zip, marker::PhantomData};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F128b, F8b, F2};

use crate::{
    parameters::SECURITY_PARAM,
    proof::{prover_preparer::ProverPreparer, prover_traverser::ProverTraverser},
    vole::{AsSecretBytes, RandomVoleP, RandomVoleV},
};
use crate::{vole::DecommitmentSerde, Circuit};

use self::verifier_traverser::VerifierTraverser;

mod prover_preparer;
mod prover_traverser;
mod transcript;
mod verifier_traverser;

/// Zero-knowledge proof of knowledge of a circuit.
#[derive(Debug, Clone)]
pub struct Proof<Vole: RandomVoleP, VoleV: RandomVoleV> {
    /// Commitment to the extended witness ($`d`$ in the paper).
    witness_commitment: Vec<F2>,
    polynomial_count: usize,
    /// Aggregated commitment to the degree-1 term coefficients for each gate in the circuit
    /// ($`\tilde a`$ in the paper).
    degree_1_commitment: F128b,
    /// Challenge generated to decommit to the VOLEs after committing to the degree coefficients.
    decommitment_challenge: [u8; SECURITY_PARAM / 8],
    /// Partial decommitment of the VOLEs.
    partial_decommitment: VoleV::Decommitment,

    // This ties the proof to the VOLE implementation used to create it.
    vole: PhantomData<Vole>,
}

impl<VoleP, VoleV> Proof<VoleP, VoleV>
where
    VoleP: RandomVoleP,
    VoleV: RandomVoleV<Decommitment = VoleP::Decommitment>,
{
    /// TODO: docstring
    pub fn proof_size_estimate(&self) -> usize {
        // This is only a part of the proof size, it does not include the partial decommitment part because this is abstracted with traits.
        let witness_commitment_bytes = self.witness_commitment.len() / 8;
        let degree_1_commitment_bytes = 16;
        let decommitment_challenge_bytes = SECURITY_PARAM / 8;

        let partial_decommitment_size = self.partial_decommitment.proof_size_estimate();

        return witness_commitment_bytes
            + degree_1_commitment_bytes
            + decommitment_challenge_bytes
            + partial_decommitment_size;
    }

    /// Create a proof of knowledge of a witness that satisfies the given circuit.
    pub fn prove<R>(circuit: &Circuit, transcript: &mut Transcript, rng: &mut R) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        let t = std::time::Instant::now();
        let mut transcript = transcript::Transcript::from(transcript);
        log::info!("0: load transcript: {:?}", t.elapsed());

        // Evaluate the circuit in the clear to get the full witness and all wire values
        let t = std::time::Instant::now();
        let mut circuit_preparer = ProverPreparer::new(circuit.max_wire_id)?;
        circuit_preparer.execute(&circuit)?;

        let (witness, wire_values, polynomial_count) = circuit_preparer.into_parts();
        log::info!("1: circuit preparer: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        // Update transcript with general public information
        transcript.append_public_values();

        // Get a set of (l + SECURITY_PARAM) random VOLEs
        let (voles, _vole_challenge) =
            VoleP::create(witness.len(), transcript.as_mut(), &witness, rng);
        log::info!("2: VoleP::create: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        // Commit to extended witness (`d` in the paper)
        let witness_commitment: Vec<F2> = zip(witness, voles.witness_mask())
            .map(|(w, u)| w - u)
            .collect();
        log::info!("3: witness_commitment: {:?}", t.elapsed());

        // TODO:
        // Add u~ to the transcript
        // Add hV to the transcript

        // Add witness commitment to the transcript and generate a challenge for each polynomial
        let t = std::time::Instant::now();
        transcript.append_witness_commitment(witness_commitment.as_slice());
        let witness_challenges = transcript.extract_witness_challenges(polynomial_count);

        // Traverse circuit to compute the coefficients for the degree 0 and 1 terms for each
        // gate / polynomial (`A_i0` and `A_i1` in the paper) and start to aggregate these with
        // the challenges.
        let mut circuit_traverser = ProverTraverser::new(wire_values, witness_challenges, voles)?;
        circuit_traverser.execute(&circuit)?;
        let (degree_0_aggregation, degree_1_aggregation, voles) = circuit_traverser.into_parts()?;

        log::info!("4: circuit_traverser.into_parts: {:?}", t.elapsed());

        let t = std::time::Instant::now();
        // Compute masks for the aggregated coefficients (`v*`, `u*` in the paper)
        let degree_0_mask = combine(voles.aggregate_commitment_masks());
        let degree_1_mask = combine(voles.aggregate_commitment_values());

        // Finish computing aggregated responses (`a~`, `b~` in the paper)
        let degree_0_commitment = degree_0_aggregation + degree_0_mask;
        let degree_1_commitment = degree_1_aggregation + degree_1_mask;

        // Add aggregated responses to transcript
        transcript.append_polynomial_commitments(&degree_0_commitment, &degree_1_commitment);
        let decommitment_challenge = transcript.extract_decommitment_challenge();

        // Decommit the VOLEs
        let partial_decommitment = voles.decommit(&decommitment_challenge);

        log::info!("5: decommit: {:?}", t.elapsed());
        // Form the proof
        Ok(Self {
            witness_commitment,
            degree_1_commitment,
            polynomial_count,
            decommitment_challenge,
            partial_decommitment,
            vole: PhantomData,
        })
    }

    /// This makes sure the proof is correctly formed e.g. everything is the right length.
    fn validate_proof(&self, voles: &VoleV) -> Result<()> {
        // There should be one witness commitment for every element in the extended witness
        // The proof and the decommitted VOLEs should agree on what this size is
        if self.witness_commitment.len() != voles.extended_witness_length() {
            bail!("Invalid proof: Did not commit to the same number of witnesses {} as there are VOLEs {}",
                self.witness_commitment.len(), voles.extended_witness_length())
        }

        Ok(())
    }

    /// Verify the proof.
    ///
    pub fn verify(&self, circuit: &Circuit, transcript: &mut Transcript) -> Result<()>
where {
        let mut transcript = transcript::Transcript::from(transcript);
        transcript.append_public_values();

        let t = std::time::Instant::now();
        // Reconstruct VOLEs and update transcript with any necessary components.
        let reconstructed_voles = VoleV::reconstruct(
            &self.partial_decommitment,
            &self.decommitment_challenge,
            transcript.as_mut(),
        );
        self.validate_proof(&reconstructed_voles)?;
        log::info!("1: VoleV::reconstruct: {:?}", t.elapsed());

        // TODO:
        // Add u~ from the proof into the transcript
        // Add hV (from VOLE) to the transcript

        // Add `d` to transcript and generate challenges for each polynomial
        let t = std::time::Instant::now();
        transcript.append_witness_commitment(self.witness_commitment.as_slice());
        log::info!("2: append_witness_commitment {:?}", t.elapsed());
        // TODO: Should we be doing something with these challenges?
        let t = std::time::Instant::now();
        let witness_challenges = transcript.extract_witness_challenges(self.polynomial_count);
        log::info!("3: extract_witness_challenges {:?}", t.elapsed());

        // Compute masked witnesses Q' = Q[..l] + d * Delta
        let t = std::time::Instant::now();
        let verifier_key = reconstructed_voles.verifier_key_array();
        let witness_commitment = &self.witness_commitment;
        let d_delta = (0..witness_commitment.len())
            .into_par_iter()
            .map(|i| {
                let witness_com = F8b::from(witness_commitment[i]);
                verifier_key.map(|key| witness_com * key)
            })
            .collect::<Vec<_>>();

        let witness_voles = reconstructed_voles.witness_voles();
        let masked_witnesses: Vec<F128b> = (0..reconstructed_voles.witness_voles().len())
            .into_par_iter()
            .map(|i| {
                let (qs, dds) = (witness_voles[i], d_delta[i]);
                let masked_witness: [F8b; 16] = zip(qs, dds)
                    .map(|(q, dd)| q + dd)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                F8b::form_superfield(&masked_witness.into())
            })
            .collect();
        log::info!("4: reconstructed voles with masks {:?}", t.elapsed());

        let t = std::time::Instant::now();
        // Combine mask VOLEs to get q*
        let validation_mask = combine(reconstructed_voles.mask_voles());

        // Run circuit traversal and get the aggregate value (part of c~)
        let mut verifier_traverser = VerifierTraverser::new(
            witness_challenges,
            reconstructed_voles.verifier_key(),
            masked_witnesses,
            circuit.max_wire_id,
        )?;
        verifier_traverser.execute(&circuit)?;
        let validation_aggregate = verifier_traverser.into_parts()?;
        log::info!("5: circuit traverser {:?}", t.elapsed());

        let t = std::time::Instant::now();
        // Finally, compute c~ = aggregate + q*
        let validation = validation_aggregate + validation_mask;
        let degree_0_commitment =
            validation - self.degree_1_commitment * reconstructed_voles.verifier_key();

        // Add aggregated responses to the transcript
        transcript.append_polynomial_commitments(&degree_0_commitment, &self.degree_1_commitment);

        // Get the VOLE decommitment challenge and make sure it's valid
        let decommitment_challenge = transcript.extract_decommitment_challenge();
        if self.decommitment_challenge != decommitment_challenge {
            bail!("Verification failed: VOLE challenge did not match expected value");
        }
        log::info!("6: last check {:?}", t.elapsed());

        Ok(())
    }
}

/// Convert a list of field elements into a single 128-bit value.
///
/// Specifically, we compute
/// $` \sum_{i = 0}^{128} v_i X^i`$,
/// where $`X`$ is [`F128b::GENERATOR`], the generator for the field.
fn combine(values: [F128b; 128]) -> F128b {
    // Start with `X^0 = 1`
    let mut power = F128b::ONE;
    let mut acc = F128b::ZERO;

    for vi in values {
        acc += vi * power;
        power *= F128b::GENERATOR;
    }
    acc
}

/// The secret material for the prover is the extended witness.
impl AsSecretBytes for Vec<F2> {
    fn as_bytes(&self) -> Vec<u8> {
        self.iter().map(|b| (*b).into()).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Cursor};

    use eyre::Result;
    use mac_n_cheese_sieve_parser::text_parser::RelationReader;
    use merlin::Transcript;
    use rand::thread_rng;
    use std::io::Write;
    use tempfile::tempdir;

    use crate::vole::insecure::{InsecureCommitments, InsecureVole};

    use super::Proof;

    #[test]
    fn header_cannot_include_plugins() {
        let plugin = "version 2.0.0;
            circuit;
            @type field 2;
            @plugin mux_v0;
            @begin
            @end ";
        let plugin_cursor = &mut Cursor::new(plugin.as_bytes());
        let reader = RelationReader::new(plugin_cursor).unwrap();
        assert!(
            Proof::<InsecureVole, InsecureCommitments>::validate_circuit_header(&reader).is_err()
        );
    }

    #[test]
    fn header_cannot_include_conversions() {
        // The conversion is from self->self because adding an extra type is a different failure case
        let trivial_conversion = "version 2.0.0;
            circuit;
            @type field 2;
            @convert(@out: 0:1, @in: 0:1);
            @begin
            @end ";
        let conversion_cursor = &mut Cursor::new(trivial_conversion.as_bytes());
        let reader = RelationReader::new(conversion_cursor).unwrap();
        assert!(
            Proof::<InsecureVole, InsecureCommitments>::validate_circuit_header(&reader).is_err()
        );
    }

    #[test]
    fn header_cannot_include_non_boolean_fields() {
        let big_field = "version 2.0.0;
            circuit;
            @type field 2305843009213693951;
            @begin
            @end ";
        let big_field_cursor = &mut Cursor::new(big_field.as_bytes());
        let reader = RelationReader::new(big_field_cursor).unwrap();
        assert!(
            Proof::<InsecureVole, InsecureCommitments>::validate_circuit_header(&reader).is_err()
        );

        let extra_field = "version 2.0.0;
            circuit;
            @type field 2;
            @type field 2305843009213693951;
            @begin
            @end ";
        let extra_field_cursor = &mut Cursor::new(extra_field.as_bytes());
        let reader = RelationReader::new(extra_field_cursor).unwrap();
        assert!(
            Proof::<InsecureVole, InsecureCommitments>::validate_circuit_header(&reader).is_err()
        );
    }

    #[test]
    fn tiny_header_works() -> eyre::Result<()> {
        let tiny_header = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
            @end ";
        let tiny_header_cursor = &mut Cursor::new(tiny_header.as_bytes());
        let reader = RelationReader::new(tiny_header_cursor)?;
        assert!(
            Proof::<InsecureVole, InsecureCommitments>::validate_circuit_header(&reader).is_ok()
        );
        Ok(())
    }

    // Get a fresh transcript
    fn transcript() -> Transcript {
        Transcript::new(b"basic happy test transcript")
    }

    // Create a proof for the given circuit and input.
    fn create_proof(
        circuit_bytes: &'static str,
        private_input_bytes: &'static str,
    ) -> Result<(Result<Proof<InsecureVole, InsecureCommitments>>, Circuit)> {
        let mut circuit_cursor = Cursor::new(circuit_bytes.as_bytes());

        let dir = tempdir().unwrap();
        let private_input_path = dir.path().join("schmivitz_private_inputs");
        let mut private_input = File::create(private_input_path.clone()).unwrap();
        writeln!(private_input, "{}", private_input_bytes).unwrap();

        let circuit = load_circuit_prover(&mut circuit_cursor, &private_input_path)?;
        let rng = &mut thread_rng();

        let proof = Proof::<InsecureVole, InsecureCommitments>::prove::<_>(
            &circuit,
            &mut transcript(),
            rng,
        );
        Ok((proof, circuit))
    }

    #[test]
    fn prove_doesnt_explode() -> Result<()> {
        let mini_circuit_bytes = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
            @end";

        let (proof, mut mini_circuit) = create_proof(mini_circuit_bytes, private_input_bytes)?;
        assert!(proof?.verify(&mut mini_circuit, &mut transcript()).is_ok());

        Ok(())
    }

    const SMALL_CIRCUIT: &str = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
          $0 ... $4 <- @private(0);
          $5 <- @add(0: $0, $0);
          $6 <- @add(0: $0, $1);
          $7 <- @add(0: $0, $2);
          $8 <- @add(0: $0, $3);
          $9 <- @add(0: $0, $4);
          $10 <- @mul(0: $0, $5);
          $11 <- @mul(0: $0, $6);
          $12 <- @mul(0: $0, $7);
          $13 <- @mul(0: $0, $8);
          $14 <- @mul(0: $0, $9);
        @end ";

    #[test]
    fn prove_works_on_slightly_larger_circuit() -> Result<()> {
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
                < 1 >;
                < 1 >;
                < 0 >;
                < 0 >;
            @end ";

        let (proof, mut small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes)?;
        assert!(proof?.verify(&mut small_circuit, &mut transcript()).is_ok());

        Ok(())
    }

    #[test]
    fn prover_and_verifier_must_input_the_same_transcript() -> Result<()> {
        let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 0 >;
            < 1 >;
            < 0 >;
            < 1 >;
        @end ";

        // This uses the output of `transcript()` as-is to prove. This should work
        let (proof, mut small_circuit) = create_proof(SMALL_CIRCUIT, private_input_bytes)?;
        assert!(proof.is_ok());

        // If we use a different transcript to verify, it'll fail
        let transcript = &mut transcript();
        transcript.append_message(b"I am but a simple verifier", b"trying to be secure");
        assert!(proof?.verify(&mut small_circuit, transcript).is_err());

        Ok(())
    }

    #[test]
    fn proof_requires_exact_number_of_challenges() -> Result<()> {
        // Create a valid proof
        let small_circuit_bytes = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 ... $4 <- @private(0);
              $5 <- @add(0: $0, $0);
              $6 <- @add(0: $0, $1);
              $7 <- @add(0: $0, $2);
              $8 <- @add(0: $0, $3);
              $9 <- @add(0: $0, $4);
              $10 <- @mul(0: $0, $5);
              $11 <- @mul(0: $0, $6);
              $12 <- @mul(0: $0, $7);
              $13 <- @mul(0: $0, $8);
              $14 <- @mul(0: $0, $9);
            @end ";
        let small_circuit_text = &mut Cursor::new(small_circuit_bytes.as_bytes());

        let dir = tempdir()?;
        let private_input_path = dir.path().join("basic_happy_small_test_path");
        let mut private_input = File::create(private_input_path.clone())?;
        let private_input_bytes = "version 2.0.0;
            private_input;
            @type field 2;
            @begin
                < 1 >;
                < 0 >;
                < 1 >;
                < 0 >;
                < 1 >;
            @end ";
        writeln!(private_input, "{}", private_input_bytes)?;

        let small_circuit = load_circuit_prover(small_circuit_text, &private_input_path)?;
        let rng = &mut thread_rng();

        let proof = Proof::<InsecureVole, InsecureCommitments>::prove::<_>(
            &small_circuit,
            &mut transcript(),
            rng,
        )?;

        // Adding an extra challenge should fail
        let mut too_many_challenges = proof.clone();
        too_many_challenges.polynomial_count = too_many_challenges.polynomial_count + 1;

        assert!(too_many_challenges
            .verify(&mut small_circuit.clone(), &mut transcript())
            .is_err());

        // Not having enough challenges should fail
        let mut too_few_challenges = proof.clone();
        too_few_challenges.polynomial_count = too_few_challenges.polynomial_count + 1;
        assert!(too_few_challenges
            .verify(&small_circuit, &mut transcript())
            .is_err());

        Ok(())
    }
}
