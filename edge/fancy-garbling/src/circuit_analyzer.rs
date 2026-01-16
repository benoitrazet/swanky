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
        FancyArithmetic::add(self, x, y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        FancyArithmetic::mul(self, x, y)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nadds += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            depth: x.depth,
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
