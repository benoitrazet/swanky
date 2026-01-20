use eyre::bail;
use mac_n_cheese_sieve_parser::WireId;
use swanky_field_binary::F2;

use crate::circuit::{Circuit, CircuitMemory, GateM};
use diet_mac_and_cheese::fields::SieveIrDeserialize;

/// A [`ProverPreparer`] allows the prover to prepare for VOLE-in-the-head by evaluating the
/// circuit in the clear and determining the full extended witness.
///
/// The total extended witness includes two types of values:
/// - Private inputs to the circuit (this is the "non-extended" witness)
/// - Outputs of non-linear (multiplication) gates (this is the "extended" part)
///
/// ## Failure modes
/// This type is only designed to be used with a VOLE-in-the-head circuit. Its methods will fail
/// if it visits a circuit where:
/// - there are gates other than `private-input`, `add`, `addc`, or `mul`
/// - there is more than one type ID used for any gate
/// - any private input to the circuit is not in $`F2`$
#[derive(Debug)]
pub(crate) struct ProverPreparer {
    /// Complete map of values on every wire in the circuit.
    wire_values: CircuitMemory<F2>,

    /// Set of wire values that correspond to elements in the extended witness.
    witness: Vec<F2>,

    /// Number of polynomials that will need challenges.
    challenge_count: usize,
}

impl ProverPreparer {
    pub(crate) fn new(max_wire_id: WireId) -> eyre::Result<Self> {
        Ok(Self {
            wire_values: CircuitMemory::new(max_wire_id),
            witness: Vec::default(),
            challenge_count: 0,
        })
    }
}

impl ProverPreparer {
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.witness.len()
    }

    /// Save a value in our wire map.
    fn save_wire(&mut self, wid: WireId, value: F2) -> eyre::Result<()> {
        // Assumption: Every wire ID will be assigned to exactly once, so if there's already a
        // value associated with a wire ID, the circuit is malformed.
        self.wire_values.insert(wid, value);
        Ok(())
    }

    /// Get the witness, wire values, and number of challenges required.
    ///
    /// These values will be empty if the circuit has not yet been traversed.
    pub(crate) fn into_parts(self) -> (Vec<F2>, CircuitMemory<F2>, usize) {
        (self.witness, self.wire_values, self.challenge_count)
    }

    /// Execute a circuit.
    pub(crate) fn execute(&mut self, circuit: &Circuit) -> eyre::Result<()> {
        let mut priv_input_pos: usize = 0;
        for g in circuit.gates.iter().cloned() {
            match g {
                GateM::Add(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    let sum = self.wire_values.get(&left) + self.wire_values.get(&right);

                    self.save_wire(dst, sum)?;
                }
                GateM::Mul(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    self.challenge_count += 1;

                    let product = self.wire_values.get(&left) * self.wire_values.get(&right);

                    // Save product to the witness and associate it with its wire ID
                    self.witness.push(product);
                    self.save_wire(dst, product)?;
                }
                GateM::AddConstant(ty, dst, left, right) => {
                    // Assumption: There is exactly one type ID for these circuits and it is F2.
                    assert_eq!(ty, 0);

                    let sum = match self.wire_values.get(&left) {
                        l_val => l_val + F2::from_number(&right)?,
                    };

                    self.save_wire(dst, sum)?;
                }
                GateM::Witness(ty, dst) => {
                    assert_eq!(ty, 0);
                    for wid in dst.start..=dst.end {
                        let f2 = circuit.private_inputs[priv_input_pos];
                        priv_input_pos += 1;

                        self.witness.push(f2);
                        self.save_wire(wid, f2)?;
                    }
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
    use rand::thread_rng;
    use std::io::Cursor;

    use mac_n_cheese_sieve_parser::text_parser::RelationReader;
    use swanky_field::FiniteRing;
    use swanky_field_binary::F2;

    use crate::circuit::CircuitIngestor;
    use crate::proof::prover_preparer::ProverPreparer;

    /// Take a string description of a circuit and parse it with the circuit preparer.
    fn prepare_circuit(circuit: &str) -> eyre::Result<ProverPreparer> {
        let rng = &mut thread_rng();
        // Generate a private input vector with 100 random inputs
        let random_private_inputs: Vec<F2> =
            (0..100).into_iter().map(|_| F2::random(rng)).collect();

        let cursor = &mut Cursor::new(circuit.as_bytes());
        let reader = RelationReader::new(cursor)?;
        let mut circ = CircuitIngestor::new_prover(random_private_inputs)?;
        reader.read(&mut circ)?;

        let circuit_loaded = circ.to_circuit();

        let mut counter: ProverPreparer = ProverPreparer::new(circuit_loaded.max_wire_id)?;
        counter.execute(&circuit_loaded)?;
        Ok(counter)
    }

    #[test]
    fn private_inputs_count_correctly() -> eyre::Result<()> {
        let private_input_only = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @private(0);
            @end ";
        let counter = prepare_circuit(private_input_only)?;
        assert_eq!(counter.count(), 3);

        let private_input_range = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 ... $3 <- @private(0);
            @end";
        let counter = prepare_circuit(private_input_range)?;
        assert_eq!(counter.count(), 4);
        Ok(())
    }

    #[test]
    fn multiplication_gates_count_correctly() -> eyre::Result<()> {
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
            @end ";
        let counter = prepare_circuit(one_mul)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let counter = prepare_circuit(many_mul)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }

    #[test]
    fn add_gates_are_not_counted_in_extended_witness() -> eyre::Result<()> {
        // These are the same circuits as in `multiplication_gates_count_correctly`, but with an
        // extra `@add` thrown in.
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @add(0: $0, $0);
            @end ";
        let counter = prepare_circuit(one_mul)?;
        assert_eq!(counter.count(), 2);

        let many_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @mul(0: $0, $0);
              $2 <- @mul(0: $0, $1);
              $3 <- @mul(0: $0, $2);
              $7 <- @add(0: $0, $2);
              $4 <- @mul(0: $0, $3);
              $5 <- @mul(0: $0, $4);
              $6 <- @mul(0: $0, $5);
            @end ";
        let counter = prepare_circuit(many_mul)?;
        assert_eq!(counter.count(), 7);
        Ok(())
    }

    #[test]
    fn add_gates_eval_correctly() -> eyre::Result<()> {
        let one_add = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @add(0: $0, $1);
            @end ";

        // This evaluates on a random input; over time we'll check them all
        let counter = prepare_circuit(one_add)?;
        assert_eq!(
            counter.wire_values.get(&0) + counter.wire_values.get(&1),
            *counter.wire_values.get(&2)
        );

        Ok(())
    }

    #[test]
    fn mul_gates_eval_correctly() -> eyre::Result<()> {
        let one_mul = "version 2.0.0;
            circuit;
            @type field 2;
            @begin
              $0 <- @private(0);
              $1 <- @private(0);
              $2 <- @mul(0: $0, $1);
            @end ";

        // This evaluates on a random input; over time we'll check them all
        let counter = prepare_circuit(one_mul)?;
        assert_eq!(
            counter.wire_values.get(&0) * counter.wire_values.get(&1),
            *counter.wire_values.get(&2)
        );

        Ok(())
    }
}
