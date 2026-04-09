use crate::{
    FancyArithmetic, FancyProj, HasModulus,
    circuit::{CircuitExecutor, CircuitRef, CircuitType},
};
use swanky_channel::Channel;

/// Static representation of arithmetic computation supported by fancy garbling.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArithmeticCircuit {
    pub(crate) gates: Vec<ArithmeticGate>,
    pub(crate) gate_moduli: Vec<u16>,
    pub(crate) input_refs: Vec<CircuitRef>,
    pub(crate) const_refs: Vec<CircuitRef>,
    pub(crate) output_refs: Vec<CircuitRef>,
    pub(crate) num_nonfree_gates: usize,
}

impl<F: FancyArithmetic + FancyProj> CircuitExecutor<F> for ArithmeticCircuit {
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

    fn modulus(&self, i: usize) -> u16 {
        self.gate_moduli[i]
    }
}

/// Arithmetic computation supported by fancy garbling.
///
/// `id` represents the gate number. `out` gives the output wire index; if `out
/// = None`, then we use the gate index as the output wire index.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ArithmeticGate {
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
    /// Add gate
    Add {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
    /// Sub gate
    Sub {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Output wire index
        out: Option<usize>,
    },
    /// Constant multiplication gate
    Cmul {
        /// Reference to input 1
        xref: CircuitRef,

        /// Constant to muiltiply by
        c: u16,

        /// Output wire index
        out: Option<usize>,
    },
    /// Multiplication gate
    Mul {
        /// Reference to input 1
        xref: CircuitRef,

        /// Reference to input 2
        yref: CircuitRef,

        /// Gate number
        id: usize,

        /// Output wire index
        out: Option<usize>,
    },
    /// Projection gate
    Proj {
        /// Reference to input 1
        xref: CircuitRef,

        /// Projection truth table
        tt: Vec<u16>,

        /// Gate number
        id: usize,

        /// Output wire index
        out: Option<usize>,
    },
}

impl std::fmt::Display for ArithmeticGate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Input { id } => write!(f, "Input {}", id),
            Self::Constant { val } => write!(f, "Constant {}", val),
            Self::Add { xref, yref, out } => write!(f, "Add ( {}, {}, {:?} )", xref, yref, out),
            Self::Sub { xref, yref, out } => write!(f, "Sub ( {}, {}, {:?} )", xref, yref, out),
            Self::Cmul { xref, c, out } => write!(f, "Cmul ( {}, {}, {:?} )", xref, c, out),
            Self::Mul {
                xref,
                yref,
                id,
                out,
            } => write!(f, "Mul ( {}, {}, {}, {:?} )", xref, yref, id, out),
            Self::Proj { xref, tt, id, out } => {
                write!(f, "Proj ( {}, {:?}, {}, {:?} )", xref, tt, id, out)
            }
        }
    }
}

impl ArithmeticCircuit {
    fn eval_to_wirelabels<F: FancyArithmetic + FancyProj>(
        &self,
        f: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<F::Item>> {
        let mut cache: Vec<Option<F::Item>> = vec![None; self.gates.len()];
        for (i, gate) in self.gates.iter().enumerate() {
            let q = self.modulus(i);
            let (zref_, val) = match *gate {
                ArithmeticGate::Input { id } => (None, inputs[id].clone()),
                ArithmeticGate::Constant { val } => (None, f.constant(val, q, channel)?),
                ArithmeticGate::Add { xref, yref, out } => (
                    out,
                    f.add(
                        cache[xref.ix].as_ref().unwrap(),
                        cache[yref.ix].as_ref().unwrap(),
                    ),
                ),
                ArithmeticGate::Sub { xref, yref, out } => (
                    out,
                    f.sub(
                        cache[xref.ix].as_ref().unwrap(),
                        cache[yref.ix].as_ref().unwrap(),
                    ),
                ),
                ArithmeticGate::Cmul { xref, c, out } => {
                    (out, f.cmul(cache[xref.ix].as_ref().unwrap(), c))
                }
                ArithmeticGate::Proj {
                    xref, ref tt, out, ..
                } => (
                    out,
                    f.proj(
                        cache[xref.ix].as_ref().unwrap(),
                        q,
                        Some(tt.to_vec()),
                        channel,
                    )?,
                ),
                ArithmeticGate::Mul {
                    xref, yref, out, ..
                } => (
                    out,
                    f.mul(
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

impl CircuitType for ArithmeticCircuit {
    type Gate = ArithmeticGate;

    fn new(ngates: Option<usize>) -> ArithmeticCircuit {
        let gates = Vec::with_capacity(ngates.unwrap_or(0));
        ArithmeticCircuit {
            gates,
            input_refs: Vec::new(),
            const_refs: Vec::new(),
            output_refs: Vec::new(),
            gate_moduli: Vec::new(),
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
        self.gate_moduli.push(modulus)
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

    fn input_mod(&self, i: usize) -> u16 {
        let r = self.input_refs[i];
        r.modulus()
    }
}

impl ArithmeticCircuit {
    /// Return the modulus of the gate indexed by `i`.
    pub fn modulus(&self, i: usize) -> u16 {
        self.gate_moduli[i]
    }
}
