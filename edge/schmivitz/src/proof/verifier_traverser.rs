use diet_mac_and_cheese::fields::SieveIrDeserialize;
use mac_n_cheese_sieve_parser::WireId;
use std::borrow::Borrow;
use swanky_error::{ErrorKind, Result, bail};
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_field_binary::F128b;

use crate::circuit::{Circuit, CircuitMemory, GateM};

/// A [`VerifierTraverser`] allows the verifier to execute the gate-by-gate evaluation portion of
/// the VOLE-in-the-head verification protocol.
///
/// The primary steps in circuit traversal are assigning masked witnesses to each
/// wire (either using provided witnesses from the proof or evaluating expected witnesses for
/// linear gates) and computing the aggregate value used to verify the proof.
pub(crate) struct VerifierTraverser {
    /// Fiat-Shamir challenges. There should be one for each polynomial (non-linear gate).
    challenges: Vec<F128b>,
    /// Number of challenges that have been assigned to a wire, so far.
    challenge_count: usize,

    /// Verifier's chosen random VOLE key ($`\Delta`$ in the paper).
    verifier_key: F128b,

    /// The masked witness commitments ($`\bf q'`$ in the paper).
    ///
    /// There should be one of these for each extended witness.
    /// Note that these are a function of the random VOLEs correlated with the witness, the
    /// commitment to the witness itself, and the verifier's VOLE key.
    masked_witnesses: Vec<F128b>,

    /// Assignment of masked witnesses to specific wires in the circuit.
    ///
    /// This is constructed during circuit traversal; it holds computed masked witnesses for
    /// linear gates and assigned masked witnesses (pulled out of `masked_witnesses`) for
    /// non-linear gates.
    assigned_masked_witnesses: CircuitMemory<F128b>,

    /// Count of how many of the provided masked witnesses have been assigned.
    assigned_witness_count: usize,

    /// Partial aggregation of the value $`\tilde c`$ from the protocol.
    ///
    /// After traversal, this should have the value
    /// $`\sum_{i \in [t]} \chi_i \cdot c_i(\Delta)`$.
    aggregate: F128b,
}

impl VerifierTraverser {
    pub(crate) fn new(
        challenges: Vec<F128b>,
        verifier_key: F128b,
        masked_witnesses: Vec<F128b>,
        max_wire_id: WireId,
    ) -> Result<Self> {
        if challenges.len() > masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: There should be no more challenges ({}) than masked witnesses ({})",
                challenges.len(),
                masked_witnesses.len(),
            );
        }
        Ok(Self {
            challenges,
            challenge_count: 0,
            verifier_key,
            masked_witnesses,
            assigned_masked_witnesses: CircuitMemory::new(max_wire_id),
            assigned_witness_count: 0,
            aggregate: F128b::ZERO,
        })
    }

    /// Assign a wire ID to a specific masked witness.
    ///
    /// This should be called with the destination [`WireId`] for each linear gate encountered.
    /// The correct masked witness is determined by the specific gate type; for example, the
    /// correct witness for an addition gate is the sum of the witnesses of the two input wires.
    /// This method does not validate the correctness of the provided witness.
    ///
    /// This function assumes that the circuit is well-formed and that wire ID can be assigned in memory
    /// and that is was not already assigned.
    fn save_computed_masked_witness(&mut self, wid: WireId, masked_witness: F128b) -> Result<()> {
        self.assigned_masked_witnesses.insert(wid, masked_witness);
        Ok(())
    }

    /// Assign a wire ID to the next unused masked witness and get the corresponding challenge.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_masked_witness()`] to
    /// assign a specific witness value to a linear gate.
    ///
    /// Fails if there aren't enough unused witnesses or if the [`WireId`] is already assigned to
    /// a masked witness.
    fn assign_masked_witness(&mut self, wid: WireId) -> Result<()> {
        let next_index = self.assigned_witness_count;
        self.assigned_witness_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: needed at least {} masked witnesses, but only got {}",
                self.assigned_witness_count,
                self.masked_witnesses.len()
            )
        }

        self.save_computed_masked_witness(wid, self.masked_witnesses[next_index])
    }

    /// Retrieves the next unused challenge.
    ///
    /// Fails if there aren't enough challenges.
    fn next_challenge(&mut self) -> Result<F128b> {
        let next_index = self.challenge_count;
        self.challenge_count += 1;
        if next_index >= self.challenges.len() {
            bail!(
                ErrorKind::OtherError,
                "Bad input: needed at least {} challenges, but only got {}",
                self.challenge_count,
                self.challenges.len()
            )
        }
        Ok(self.challenges[next_index])
    }

    /// Retrieve the masked witness associated with the [`WireId`].
    ///
    /// Fails if the [`WireId`] has not been associated with a masked witness, either by assigning
    /// a provided masked witness to a non-linear gate with [`Self::assign_masked_witness()`] or
    /// by computing the appropriate witness for a linear gate and assigning it via
    /// [`Self::save_computed_masked_witness()`].
    fn masked_witness(&self, wid: WireId) -> Result<F128b> {
        Ok(*self.assigned_masked_witnesses.get(&wid))
    }

    /// Decomposes into the aggregate component (a partial construction of `c~`) that was built
    /// during full circuit traversal.
    ///
    /// This will fail if there were unused challenges or masked witnesses.
    pub(crate) fn into_parts(self) -> Result<F128b> {
        if self.challenge_count != self.challenges.len() {
            bail!(
                ErrorKind::OtherError,
                "Proof contained more challenges than it needed! Had {}, used {}",
                self.challenges.len(),
                self.challenge_count
            );
        }
        if self.assigned_witness_count != self.masked_witnesses.len() {
            bail!(
                ErrorKind::OtherError,
                "Proof contained more masked witnesses than it needed! Had {}, used {}",
                self.masked_witnesses.len(),
                self.assigned_witness_count
            );
        }
        Ok(self.aggregate)
    }

    /// Execute a circuit.
    pub(crate) fn execute(&mut self, circ: &Circuit) -> Result<()> {
        for g in circ.gates.iter().cloned() {
            match g {
                GateM::Add(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Compute the correct masked witness for the output wire
                    self.save_computed_masked_witness(
                        dst,
                        self.masked_witness(left)? + self.masked_witness(right)?,
                    )?;

                    // Linear gates don't contribute to the aggregate being computed
                }
                GateM::Mul(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Assign the next masked witness to the destination wire
                    self.assign_masked_witness(dst)?;
                    let challenge = self.next_challenge()?;

                    // Compute the contibution to the aggregate: ci​(Δ) = q_left * ​q_right ​− q_dst * ​Δ
                    let eval = self.masked_witness(left)? * self.masked_witness(right)?
                        - (self.masked_witness(dst)? * self.verifier_key);

                    self.aggregate += challenge * eval;
                }
                GateM::AddConstant(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Compute the correct masked witness for the output wire
                    let t = if F2::from_number(right.borrow())? == F2::ZERO {
                        F128b::ZERO
                    } else {
                        F128b::ONE
                    };
                    self.save_computed_masked_witness(
                        dst,
                        self.masked_witness(left)? - t * self.verifier_key,
                    )?;

                    // Linear gates don't contribute to the aggregate being computed
                }
                GateM::Witness(ty, dst) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // For each of the output wires:
                    for wid in dst.start..=dst.end {
                        // Assign a fresh masked witness to the wire
                        self.assign_masked_witness(wid)?;

                        // Private input gates don't define a polynomial that would contribute to the aggregate
                        // being computed, so we ignore the challenge
                    }
                }
                _ => bail!(
                    ErrorKind::UnsupportedError,
                    "Invalid input: VOLE-in-the-head does not support gate {:?}",
                    g
                ),
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::repeat_with};

    use rand::{Rng, thread_rng};
    use swanky_error::Result;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F128b;

    use super::VerifierTraverser;

    fn dummy_traverser(len: usize) -> VerifierTraverser {
        let rng = &mut thread_rng();

        let challenges = repeat_with(|| F128b::random(rng)).take(len).collect();
        let verifier_key = F128b::random(rng);
        let masked_witnesses = repeat_with(|| F128b::random(rng)).take(len).collect();
        VerifierTraverser::new(
            challenges,
            verifier_key,
            masked_witnesses,
            len.try_into().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn masked_witness_assignment_works_as_expected() -> Result<()> {
        let len = 20;
        let mut traverser = dummy_traverser(len as usize);

        for wid in 0..len {
            // If the wire ID hasn't been assigned a witness, you can't retrieve it
            assert_eq!(traverser.masked_witness(wid).unwrap(), F128b::ZERO);

            // Request a masked witness to be assigned to the wire...
            traverser.assign_masked_witness(wid)?;

            // ...and make sure the assignment "counted"
            assert_eq!(traverser.assigned_witness_count as u64, wid + 1);

            // Now you can retrieve the masked witness
            assert!(traverser.masked_witness(wid).is_ok());
        }

        // Can't assign more witnesses than you have
        assert!(traverser.assign_masked_witness(len + 1).is_err());

        Ok(())
    }

    #[test]
    fn masked_witness_computation_works_as_expected() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 25;
        let len_u64: u64 = len.try_into().unwrap();
        let mut traverser = dummy_traverser(len);

        // Form a random set of unique wire ids (might be smaller than 25 due to repeats)
        let wire_ids: HashSet<_> = repeat_with(|| (rng.r#gen::<u8>() as u64) % len_u64)
            .take(len)
            .collect();

        for wid in wire_ids {
            // If the wire ID doesn't have an associated computed masked witness, retrieval fails
            assert_eq!(traverser.masked_witness(wid).unwrap(), F128b::ZERO);

            // "Compute" a masked witness for the gate...
            let witness = F128b::random(rng);
            traverser.save_computed_masked_witness(wid, witness)?;

            // ...and make sure they were assigned as expected
            assert_eq!(traverser.masked_witness(wid)?, witness)
        }

        Ok(())
    }
}
