use crate::{
    FancyBinary, HasModulus,
    circuit::{
        CircuitBuilder, CircuitExecutor, CircuitRef, CircuitType, EvaluableCircuit, GateType,
    },
};
use swanky_channel::Channel;

/// Static representation of binary computation supported by fancy garbling.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BinaryCircuit {
    pub(crate) gates: Vec<BinaryGate>,
    pub(crate) input_refs: Vec<CircuitRef>,
    pub(crate) const_refs: Vec<CircuitRef>,
    pub(crate) output_refs: Vec<CircuitRef>,
    pub(crate) num_nonfree_gates: usize,
}

impl<F: FancyBinary> CircuitExecutor<F> for BinaryCircuit {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[<F as crate::Fancy>::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<<F as crate::Fancy>::Item>> {
        self.eval_to_wirelabels(backend, inputs, channel)
    }

    fn ninputs(&self) -> usize {
        self.input_refs.len()
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

/// Binary computation supported by fancy garbling.
///
/// `id` represents the gate number. `out` gives the output wire index; if `out
/// = None`, then we use the gate index as the output wire index.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BinaryGate {
    /// Input value
    Input {
        /// Gate number
        id: usize,
    },
    /// Constant value
    Constant {
        /// Value of constant
        val: u16,
    },

    /// Xor gate
    Xor {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
    /// And gate
    And {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Gate number
        id: usize,

        /// Output wire index
        out: Option<usize>,
    },
    /// Not gate
    Inv {
        /// Reference to input
        xref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
}

impl std::fmt::Display for BinaryGate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Input { id } => write!(f, "Input {}", id),
            Self::Constant { val } => write!(f, "Constant {}", val),
            Self::Xor { xref, yref, out } => write!(f, "Xor ( {}, {}, {:?} )", xref, yref, out),
            Self::And {
                xref,
                yref,
                id,
                out,
            } => write!(f, "And ( {}, {}, {}, {:?} )", xref, yref, id, out),
            Self::Inv { xref, out } => write!(f, "Inv ( {}, {:?} )", xref, out),
        }
    }
}

impl<F: FancyBinary> EvaluableCircuit<F> for BinaryCircuit {
    fn eval_to_wirelabels(
        &self,
        f: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<F::Item>> {
        let mut cache: Vec<Option<F::Item>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let q = 2;
            let (zref_, val) = match *gate {
                BinaryGate::Input { id } => (None, inputs[id].clone()),
                BinaryGate::Constant { val } => (None, f.constant(val, q, channel)?),
                BinaryGate::Inv { xref, out } => (out, f.negate(cache[xref.ix].as_ref().unwrap())),
                BinaryGate::Xor { xref, yref, out } => (
                    out,
                    f.xor(
                        cache[xref.ix].as_ref().unwrap(),
                        cache[yref.ix].as_ref().unwrap(),
                    ),
                ),
                BinaryGate::And {
                    xref, yref, out, ..
                } => (
                    out,
                    f.and(
                        cache[xref.ix].as_ref().unwrap(),
                        cache[yref.ix].as_ref().unwrap(),
                        channel,
                    )?,
                ),
            };
            cache[zref_.unwrap_or(i)] = Some(val);
        }
        let mut outputs = Vec::with_capacity(self.noutputs());
        for r in self.get_output_refs().iter() {
            let wirelabel = cache[r.ix].as_ref().unwrap();
            outputs.push(wirelabel.clone());
        }
        Ok(outputs)
    }
}

impl GateType for BinaryGate {
    fn make_constant(val: u16) -> Self {
        Self::Constant { val }
    }

    fn make_input(id: usize) -> Self {
        Self::Input { id }
    }
}

impl CircuitType for BinaryCircuit {
    type Gate = BinaryGate;

    fn new(ngates: Option<usize>) -> Self {
        let gates = Vec::with_capacity(ngates.unwrap_or(0));
        Self {
            gates,
            input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            num_nonfree_gates: 0,
        }
    }

    fn push_gates(&mut self, gate: Self::Gate) {
        self.gates.push(gate)
    }

    fn push_const_ref(&mut self, xref: CircuitRef) {
        self.const_refs.push(xref)
    }

    fn push_output_ref(&mut self, xref: CircuitRef) {
        self.output_refs.push(xref)
    }

    fn push_input_ref(&mut self, xref: CircuitRef) {
        self.input_refs.push(xref)
    }

    fn push_modulus(&mut self, modulus: u16) {
        assert_eq!(modulus, 2);
    }

    fn increment_nonfree_gates(&mut self) {
        self.num_nonfree_gates += 1;
    }

    fn get_num_nonfree_gates(&self) -> usize {
        self.num_nonfree_gates
    }

    fn get_output_refs(&self) -> &[CircuitRef] {
        &self.output_refs
    }

    fn get_input_refs(&self) -> &[CircuitRef] {
        &self.input_refs
    }

    fn input_mod(&self, _: usize) -> u16 {
        2
    }
}

impl FancyBinary for CircuitBuilder<BinaryCircuit> {
    fn xor(&mut self, xref: &Self::Item, yref: &Self::Item) -> Self::Item {
        let gate = BinaryGate::Xor {
            xref: *xref,
            yref: *yref,
            out: None,
        };

        self.gate(gate, xref.modulus())
    }

    fn negate(&mut self, xref: &Self::Item) -> Self::Item {
        let gate = BinaryGate::Inv {
            xref: *xref,
            out: None,
        };
        self.gate(gate, xref.modulus())
    }

    fn and(
        &mut self,
        xref: &Self::Item,
        yref: &Self::Item,
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        let gate = BinaryGate::And {
            xref: *xref,
            yref: *yref,
            id: self.get_next_ciphertext_id(),
            out: None,
        };

        Ok(self.gate(gate, xref.modulus()))
    }
}
