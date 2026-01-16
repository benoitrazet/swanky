//! Fancy object to compute the multiplicative depth of a computation.

use crate::{
    FancyArithmetic, FancyBinary,
    errors::FancyError,
    fancy::{Fancy, FancyInput, FancyReveal, HasModulus},
};
use eyre::{ErrReport, eyre};
use std::cmp::max;
use std::error::Error;

/// An instantiation of [`FancyInput::Item`] used by [`CircuitAnalyzer`].
///
/// A dummy FancyItem which is returned when profiling a [`Fancy`] circuit.
/// The [`AnalyzerItem`] contains the wire modulus and the depth of the computation.
/// This is because [`Fancy::Item`] needs to implement [`HasModulus`].
#[derive(Clone, Debug)]
pub struct AnalyzerItem {
    modulus: u16,
    depth: usize,
}

impl HasModulus for AnalyzerItem {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

/// Error from the [`CircuitAnalyzer`] fancy object
///
/// This error either wraps any underlying error thrown by
/// [`Fancy`] with eyre or returns an error when trying to run
/// the [`CircuitAnalyzer`] on projection gates.
#[derive(Debug)]
pub enum AnalyzerError {
    /// Projection is unsupported by the depth informer
    ProjUnsupported,
    /// Error from Fancy library.
    Underlying(ErrReport),
}

impl From<FancyError> for AnalyzerError {
    fn from(e: FancyError) -> Self {
        AnalyzerError::Underlying(eyre!(e))
    }
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::ProjUnsupported => writeln!(f, "Projection unsupported"),
            Self::Underlying(e) => writeln!(f, "Fancy error: {}", e),
        }
    }
}
impl Error for AnalyzerError {}

/// Fancy Object which computes information about the circuit of interest to FHE.
///
/// A [`Fancy`] object which counts gates in a binary circuit.
///
/// Specifically, [`CircuitAnalyzer`] stores the number of inputs,
/// ands, xors, negations, constants, multiplication, addition, subtraction,
/// constant operations and multiplication depth of the circuits. This
/// information is especially useful for pre-processing authenticated
/// garbling circuits.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct CircuitAnalyzer {
    ninputs: usize,
    nconstants: usize,
    nands: usize,
    nxors: usize,
    nnegs: usize,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    mul_depth: usize,
}

impl std::fmt::Display for CircuitAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "computation info:")?;
        writeln!(f, "   number of inputs: {:16}", self.ninputs)?;
        writeln!(f, "   number of constants: {:16}", self.nconstants)?;
        writeln!(f, "   number of additions: {:16}", self.nadds)?;
        writeln!(f, "   number of subtractions: {:16}", self.nsubs)?;
        writeln!(f, "   number of cmuls: {:16}", self.ncmuls)?;
        writeln!(f, "   number of muls: {:16}", self.nmuls)?;
        writeln!(f, "   number of ands: {:16}", self.nands)?;
        writeln!(f, "   number of xors: {:16}", self.nxors)?;
        writeln!(f, "   number of negations: {:16}", self.nnegs)?;
        writeln!(
            f,
            "   total number of arithmetic gates(ADD, SUB, MUL, CMUL): {:16}",
            self.nadds + self.nsubs + self.ncmuls + self.nmuls
        )?;
        writeln!(
            f,
            "   total number of boolean gates (AND, XOR): {:16}",
            self.nands + self.nxors
        )?;
        writeln!(f, "   multiplicative depth: {:16}", self.mul_depth)?;
        Ok(())
    }
}

impl CircuitAnalyzer {
    /// Create a new [`CircuitAnalyzer`] and sets all the gate
    /// counts to 0.
    pub fn new() -> CircuitAnalyzer {
        Default::default()
    }
    /// Return the number of AND gates in the circuit
    pub fn nands(&self) -> usize {
        self.nands
    }
    /// Return the number of input wires of the circuit
    pub fn ninputs(&self) -> usize {
        self.ninputs
    }
}

impl FancyInput for CircuitAnalyzer {
    type Item = AnalyzerItem;
    type Error = AnalyzerError;

    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.ninputs += moduli.len();
        Ok(moduli
            .iter()
            .map(|q| AnalyzerItem {
                modulus: *q,
                depth: 0,
            })
            .collect())
    }

    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error> {
        self.receive_many(moduli)
    }
}

impl FancyBinary for CircuitAnalyzer {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nxors += 1;
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            // Same depth as an ADD
            depth: max(x.depth, y.depth),
        })
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            // Same depth as a MUL
            depth: max(x.depth, y.depth) + 1,
        })
    }
    fn or(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        self.nnegs += 3;
        // Fancy binary's AND gate calls the underlying arithmetic multiplication
        self.nmuls += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            // This is because OR in swanky invokes an AND gate
            depth: max(x.depth, y.depth) + 1,
        })
    }
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nnegs += 1;

        // Fancy implements negation with one constant gate and one XOR
        self.nconstants += 1;
        self.nxors += 1;

        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            // Same depth as a XOR, except that negation is a unary gate
            depth: x.depth,
        })
    }
    fn adder(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        carry_in: Option<&Self::Item>,
    ) -> Result<(Self::Item, Self::Item), Self::Error> {
        // Fancy implements adders with 5 XORs and 2 ANDs
        self.nands += 2;
        self.nxors += 5;
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += 2;
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 5;
        // We need to take the carry_in's depth into account as it may come from elsewhere in the circuit
        let carry_depth = { if let Some(v) = carry_in { v.depth } else { 0 } };
        Ok((
            AnalyzerItem {
                modulus: x.modulus,
                // An adder is comprised of two ANDS, which increase the multiplication depth
                // by 2. We first however need to check which of the inputs has highest depths.
                depth: max(max(x.depth, y.depth), carry_depth) + 2,
            },
            AnalyzerItem {
                modulus: x.modulus,
                depth: max(max(x.depth, y.depth), carry_depth) + 2,
            },
        ))
    }
    fn and_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        self.nands += args.len();
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
            // The gates comprising this function are all sequential
            depth: args.iter().fold(args[0].depth, |acc, x| max(acc, x.depth)) + args.len(),
        })
    }
    fn or_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        // Fancy implements OR with 3 NEGs and 1 AND.
        self.nands += args.len();
        self.nnegs += 3 * args.len();
        // Recall that a negation is made of 1 constant input and 1 XOR
        self.nconstants += args.len();
        self.nxors += args.len();
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += args.len();
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
            depth: args.iter().fold(args[0].depth, |acc, x| max(acc, x.depth)) + args.len(),
        })
    }
    fn xor_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        self.nxors += args.len();
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
            depth: args.iter().fold(args[0].depth, |acc, x| max(acc, x.depth)),
        })
    }
    fn mux_constant_bits(
        &mut self,
        x: &Self::Item,
        _b1: bool,
        _b2: bool,
    ) -> Result<Self::Item, Self::Error> {
        self.nnegs += 1;
        self.nconstants += 2;

        // Fancy implements negation with one constant gate and one XOR
        self.nconstants += 1;
        self.nxors += 1;

        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: x.depth,
        })
    }
    fn mux(
        &mut self,
        b: &Self::Item,
        x: &Self::Item,
        y: &Self::Item,
    ) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        self.nxors += 2;
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += 2;
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 2;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: max(max(x.depth, y.depth), b.depth) + 1,
        })
    }
}

impl FancyArithmetic for CircuitAnalyzer {
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nadds += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        })
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nsubs += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        })
    }

    fn cmul(&mut self, x: &Self::Item, _y: u16) -> Result<Self::Item, Self::Error> {
        self.ncmuls += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: x.depth + 1,
        })
    }

    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nmuls += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth) + 1,
        })
    }

    fn proj(
        &mut self,
        _x: &Self::Item,
        _q: u16,
        _tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error> {
        Err(AnalyzerError::ProjUnsupported)
    }
}

impl Fancy for CircuitAnalyzer {
    type Item = AnalyzerItem;
    type Error = AnalyzerError;

    fn constant(&mut self, _val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.nconstants += 1;
        Ok(AnalyzerItem {
            modulus: q,
            depth: 0,
        })
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        self.mul_depth = max(self.mul_depth, x.depth);
        Ok(None)
    }
}

impl FancyReveal for CircuitAnalyzer {
    fn reveal(&mut self, _x: &Self::Item) -> Result<u16, Self::Error> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BinaryGadgets;
    #[test]
    fn single_and_gate_count_is_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            let y = analyzer_test.bin_encode(y, nbits).unwrap();
            let _c = analyzer_test.bin_and(&x, &y);
        }

        assert_eq!(analyzer_test.ninputs, 128);
        assert_eq!(analyzer_test.nands, 64);
        assert_eq!(analyzer_test.nxors, 0);
        assert_eq!(analyzer_test.nconstants, 0);
        assert_eq!(analyzer_test.nnegs, 0);
    }
    #[test]
    fn binary_addition_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            let y = analyzer_test.bin_encode(y, nbits).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_addition(&x, &y);
        }

        assert_eq!(analyzer_test.ninputs, 128);
        assert_eq!(analyzer_test.nands, 64 * 2);
        assert_eq!(analyzer_test.nxors, 64 * 5);
        assert_eq!(analyzer_test.nconstants, 0);
        assert_eq!(analyzer_test.nnegs, 0);
    }
    #[test]
    fn binary_multiplication_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            let y = analyzer_test.bin_encode(y, nbits).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_mul(&x, &y);
        }

        // In binary multiplication there are :
        // - 64 * 64 explicit ANDs, i.e. pairwise ANDS between parties input wires.
        // - Sum(65 to 128) binary additions. Recall that in multiplication the input
        //   size grows by 1 bit each round until each 2 times the size of the initial
        //   input (i.e. 64 * 2)
        assert_eq!(analyzer_test.ninputs, 128);
        assert_eq!(analyzer_test.nands, (65..128).sum::<usize>() * 2 + 64 * 64);
        assert_eq!(analyzer_test.nxors, (65..128).sum::<usize>() * 5);
        assert_eq!(analyzer_test.nconstants, 64);
        assert_eq!(analyzer_test.nnegs, 0);
    }
    #[test]
    fn binary_twos_complement_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_twos_complement(&x);
        }

        assert_eq!(analyzer_test.ninputs, 64);
        assert_eq!(analyzer_test.nands, 63 * 2);
        assert_eq!(analyzer_test.nxors, 63 * 5 + 3 + 64);
        assert_eq!(analyzer_test.nconstants, 64 + 64);
        assert_eq!(analyzer_test.nnegs, 64);
    }
}
