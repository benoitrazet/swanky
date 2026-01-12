use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::WireId;
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};

use crate::circuit::{Circuit, CircuitMemory, GateM};
use crate::vole::RandomVoleP;

/// A [`ProverTraverser`] allows the prover to execute the gate-by-gate evaluation portion of the
/// VOLE-in-the-head protocol.
///
/// The primary steps in circuit traversal include assigning VOLEs to each wire and
/// computing the two aggregated values used in the proof.
pub(crate) struct ProverTraverser<Vole> {
    /// Map containing the full set of wire values for the entire circuit.
    ///
    /// Note: For the currently-accepted set of gates, it is actually only necessary for this to
    /// contain the input wires for multiplication gates, but the current structure of the
    /// [`ProverPreparer`](crate::proof::prover_preparer::ProverPreparer) will produce
    /// the full set of wire values.
    wire_values: CircuitMemory<F2>,
    /// Fiat-Shamir challenges. There should be one for each polynomial (e.g. non-linear gate).
    challenges: Vec<F128b>,

    /// Random VOLE values. There should be one for each extended witness value.
    voles: Vole,
    /// Assignment of VOLE values to specific wires in the circuit.
    ///
    /// This is constructed during circuit traversal; it holds computed output VOLE values for
    /// linear gates and assigned VOLE values (pulled out of `voles`) for non-linear gates.
    assigned_voles: CircuitMemory<F128b>,
    /// Count of how many of the custom VOLEs have been assigned.
    vole_assignment_count: usize,
    /// Count of how many of the challenges have been assigned to polynomials (non-linear gates).
    challenge_count: usize,

    /// Partial aggregation of the value $`\tilde a`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,1}`$$.
    aggregate_degree_0: F128b,
    /// Partial aggregation of the value $`\tilde b`$ from the protocol.
    ///
    /// After traversal, this should have the value $$`\sum_{i \in [t]} \chi_i \cdot A_{i,0}`$$.
    aggregate_degree_1: F128b,
}

impl<Vole: RandomVoleP> ProverTraverser<Vole> {
    /// Create a new circuit traverser.
    ///
    /// Requirements on inputs:
    /// - The `wire_values` must contain a corresponding value for the input and output wires on
    ///   every non-linear gate;
    /// - The challenges must correspond to the number of polynomials. In this setting, that must
    ///   be no greater than the length of the extended witness (as defined by the [`RandomVole`]);
    /// - The [`RandomVole::extended_witness_length()`] must be large enough to have a VOLE
    ///   corresponding to every gate in the extended witness.
    pub(crate) fn new(
        wire_values: CircuitMemory<F2>,
        challenges: Vec<F128b>,
        voles: Vole,
    ) -> Result<Self> {
        if wire_values.len() < challenges.len()
            || voles.extended_witness_length() < challenges.len()
        {
            bail!(
                "Bad input: Length of challenges ({}), extended witness ({}), and VOLEs ({}) did not meet requirements",
                challenges.len(),
                wire_values.len(),
                voles.extended_witness_length(),
            );
        }

        let max_wire_id = wire_values.len() as u64;
        Ok(Self {
            wire_values,
            challenges,

            voles,
            assigned_voles: CircuitMemory::new(max_wire_id),
            vole_assignment_count: 0,
            challenge_count: 0,

            aggregate_degree_0: F128b::ZERO,
            aggregate_degree_1: F128b::ZERO,
        })
    }

    /// Retrieve the wire value associated with the [`WireId`].
    ///
    /// It assumes the circuit is well-formed and the wire requested has been previously assigned.
    fn wire_value(&self, wid: WireId) -> Result<F2> {
        Ok(*self.wire_values.get(&wid))
    }

    /// Retrieve the VOLE value associated with the [`WireId`].
    ///
    /// It assumes the [`WireId`] has not been associated with a VOLE, either by assigning
    /// a new VOLE to a non-linear gate with [`Self::assign_vole()`] or computing the appropriate
    /// VOLE for a linear gate and assigning it via [`Self::save_computed_vole()`].
    fn vole(&self, wid: WireId) -> Result<F128b> {
        Ok(*self.assigned_voles.get(&wid))
    }

    /// Associates the given VOLE with the [`WireId`].
    ///
    /// This should be called with the destination [`WireId`] for each linear gate encountered.
    /// The correct `vole` value is determined by the specific gate type; for example, the correct
    /// VOLE for an addition gate is the sum of the VOLEs of the two input wires. This method
    /// does not validate the correctness of the VOLE.
    ///
    /// This function assumes that the circuit is well-formed and that wire ID can be assigned in memory
    /// and that is was not already assigned.
    fn save_computed_vole(&mut self, wid: WireId, vole: F128b) -> Result<()> {
        self.assigned_voles.insert(wid, vole);
        Ok(())
    }

    /// Assigns an unused VOLE to the wire ID.
    ///
    /// This should be called with the destination [`WireId`] for each non-linear gate.
    /// It should _not_ be used with linear gates! Use [`Self::save_computed_vole()`] to
    /// assign a VOLE value to a linear gate.
    ///
    /// Fails if there aren't enough VOLEs or if the [`WireId`] is already assigned to a VOLE.
    fn assign_vole(&mut self, wid: WireId) -> Result<()> {
        let next_index = self.vole_assignment_count;
        self.vole_assignment_count += 1;

        // These two checks should be equivalent because we checked at construction that the
        // challenge list is exactly the extended witness length.
        if next_index >= self.voles.extended_witness_length() {
            bail!(
                "Bad input: needed at least {} VOLEs, but only got {}",
                self.vole_assignment_count,
                self.voles.extended_witness_length()
            )
        }

        self.save_computed_vole(wid, self.voles.vole_mask(next_index)?)
    }

    /// Retrieves the next unused challenge.
    ///
    /// Fails if there aren't enough challenges.
    fn next_challenge(&mut self) -> Result<F128b> {
        let next_index = self.challenge_count;
        self.challenge_count += 1;
        if next_index >= self.challenges.len() {
            bail!(
                "Bad input: needed at least {} challenges, but only got {}",
                self.challenge_count,
                self.challenges.len()
            )
        }
        Ok(self.challenges[next_index])
    }

    /// Decomposes into the aggregate components that we constructed during the
    /// full circuit traversal.
    ///
    /// The components that were passed to [`Self::new()`] are returned unchanged.
    ///
    /// This will fail if there were unused challenges or VOLEs.
    pub(crate) fn into_parts(self) -> Result<(F128b, F128b, Vole)> {
        if self.challenge_count != self.challenges.len() {
            bail!(
                "Traversal contained more challenges than it needed! Had {}, used {}",
                self.challenges.len(),
                self.challenge_count
            );
        }
        if self.vole_assignment_count != self.voles.extended_witness_length() {
            bail!(
                "Traversal contained more VOLEs than it needed! Had {}, used {}",
                self.voles.extended_witness_length(),
                self.vole_assignment_count
            );
        }
        Ok((self.aggregate_degree_0, self.aggregate_degree_1, self.voles))
    }

    /// Execute a circuit.
    pub(crate) fn execute(&mut self, circ: &Circuit) -> Result<()> {
        for g in circ.gates.iter().cloned() {
            match g {
                GateM::Add(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Compute the correct VOLE for the output wire
                    let sum_vole = self.vole(left)? + self.vole(right)?;
                    self.save_computed_vole(dst, sum_vole)?;

                    // Linear gates don't contribute to the aggregated values being computed
                }
                GateM::Mul(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Assign a fresh VOLE to the output wire and get the corresponding challenge
                    self.assign_vole(dst)?;
                    let challenge = self.next_challenge()?;

                    // Compute coefficient values `A_i1` and `A_i0` (respectively). These are derived from the
                    // `c_i(X)` polynomial defined in the paper -- see Fig 7 and page 32-33 for details.
                    let degree_0_coeff = self.vole(left)? * self.vole(right)?;
                    let degree_1_coeff = self.wire_value(right)? * self.vole(left)?
                        + self.wire_value(left)? * self.vole(right)?
                        - self.vole(dst)?;

                    self.aggregate_degree_0 += challenge * degree_0_coeff;
                    self.aggregate_degree_1 += challenge * degree_1_coeff;
                }
                GateM::AddConstant(ty, dst, left, _right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Compute the correct VOLE for the output wire
                    let sum_vole = self.vole(left)?;
                    self.save_computed_vole(dst, sum_vole)?;

                    // Linear gates don't contribute to the aggregated values being computed
                }
                GateM::Witness(ty, dst) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    // Assign a fresh VOLE to each of the output wires
                    for wid in dst.start..=dst.end {
                        self.assign_vole(wid)?;
                    }

                    // Private input gates don't define a polynomial that would contribute to the aggregated
                    // coefficients being computed
                }
                _ => bail!(
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
    use std::iter::repeat_with;

    use eyre::Result;
    use merlin::Transcript;
    use rand::thread_rng;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F128b, F2};

    use super::ProverTraverser;
    use crate::{
        circuit::CircuitMemory,
        vole::{insecure::InsecureVole, RandomVoleP},
    };

    fn dummy_traverser(len: usize) -> ProverTraverser<InsecureVole> {
        let transcript = &mut Transcript::new(b"dummy for tests");
        let rng = &mut thread_rng();
        let secret: Vec<F2> = Vec::new();

        let (voles, _) = InsecureVole::create(len, transcript, &secret, rng);
        let challenges = repeat_with(|| F128b::random(rng)).take(len).collect();
        let len_u64: u64 = len.try_into().unwrap();
        ProverTraverser::new(CircuitMemory::new(len_u64 - 1), challenges, voles).unwrap()
    }

    #[test]
    fn vole_assignment_works_as_expected() -> Result<()> {
        let len = 20;
        let mut traverser = dummy_traverser(len);
        // Assume every gate is non-linear, for fun
        let non_linear_gates: Vec<F2> =
            traverser.wire_values.get_memory().iter().copied().collect();

        for (id, _) in non_linear_gates.iter().enumerate() {
            let gate = id as u64;
            // If the VOLE hasn't been assigned, you can't retrieve it
            assert_eq!(traverser.vole(gate).unwrap(), F128b::ZERO);

            // Request a VOLE to be assigned to the wire...
            traverser.assign_vole(gate)?;

            // ...and make sure the assignment is in order wrt the VOLE indexes (0, 1, 2...)
            assert_eq!(traverser.vole_assignment_count, id + 1);

            // Now you can retrieve the VOLE
            assert!(traverser.vole(gate).is_ok());
        }

        // Can't assign more VOLEs than you have
        assert!(traverser.assign_vole(len as u64).is_err());

        Ok(())
    }

    #[test]
    fn vole_computation_works_as_expected() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 4;
        let mut traverser = dummy_traverser(len);

        // Assume every gate is linear, for fun
        let linear_gates: Vec<F2> = traverser.wire_values.get_memory().iter().copied().collect();
        for (id, _) in linear_gates.iter().enumerate() {
            let wid = id as u64;
            // If VOLEs haven't been computed, you can't retrieve them
            assert_eq!(traverser.vole(wid).unwrap(), F128b::ZERO);

            // "Compute" a VOLE for the gate...
            let vole = F128b::random(rng);
            traverser.save_computed_vole(wid, vole)?;

            // ...and make sure they were assigned as expected
            assert_eq!(traverser.vole(wid)?, vole)
        }

        Ok(())
    }

    #[test]
    fn voles_cannot_be_assigned_and_computed() -> Result<()> {
        let rng = &mut thread_rng();
        let len = 4;
        let mut traverser = dummy_traverser(len);

        // Assume every gate is linear, for fun
        let linear_gates: Vec<F2> = traverser.wire_values.get_memory().iter().copied().collect();
        for id in (0..2).into_iter() {
            let wid = id as u64;
            // If VOLEs haven't been computed/assigned, you can't retrieve them
            assert_eq!(traverser.vole(wid).unwrap(), F128b::ZERO);

            // "Compute" a VOLE for the wire
            let vole = F128b::random(rng);
            traverser.save_computed_vole(wid, vole)?;

            // The value stored is extremely unlikely to be zero
            assert!(*traverser.assigned_voles.get(&wid) != F128b::ZERO);
        }

        for id in (2..linear_gates.len()).into_iter() {
            let wid = id as u64;
            // If VOLEs haven't been computed/assigned, you can't retrieve them
            assert_eq!(traverser.vole(wid).unwrap(), F128b::ZERO);

            // Assign a new VOLE for the wire
            traverser.assign_vole(wid)?;

            // The value stored is extremely unlikely to be zero
            assert!(*traverser.assigned_voles.get(&wid) != F128b::ZERO);
        }

        Ok(())
    }
}
