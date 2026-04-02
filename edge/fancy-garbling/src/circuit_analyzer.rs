//! Fancy object to profile a fancy circuit and compute stats such as the multiplicative depth
//! or the number of boolean and arithmetic gates in a circuit.
use crate::{
    FancyArithmetic, FancyBinary,
    fancy::{Fancy, HasModulus},
};
use std::cmp::max;
use swanky_channel::Channel;
use swanky_error::ErrorKind;

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

impl FancyBinary for CircuitAnalyzer {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.nxors += 1;
        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 1;
        AnalyzerItem {
            modulus: x.modulus,
            // Same depth as an ADD
            depth: max(x.depth, y.depth),
        }
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.nands += 1;
        // Fancy's AND gate calls the underlying arithmetic multiplication
        self.nmuls += 1;
        Ok(AnalyzerItem {
            modulus: x.modulus,
            // Same depth as a MUL
            depth: max(x.depth, y.depth) + 1,
        })
    }
    fn or(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
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
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        self.nnegs += 1;

        // Fancy implements negation with one constant gate and one XOR
        self.nconstants += 1;
        self.nxors += 1;

        // Fancy's XOR gate calls the underlying arithmetic addition
        self.nadds += 1;
        AnalyzerItem {
            modulus: x.modulus,
            // Same depth as a XOR, except that negation is a unary gate
            depth: x.depth,
        }
    }
}

impl FancyArithmetic for CircuitAnalyzer {
    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.nadds += 1;
        AnalyzerItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        }
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        self.nsubs += 1;
        AnalyzerItem {
            modulus: x.modulus,
            depth: max(x.depth, y.depth),
        }
    }

    fn cmul(&mut self, x: &Self::Item, _y: u16) -> Self::Item {
        self.ncmuls += 1;
        AnalyzerItem {
            modulus: x.modulus,
            depth: x.depth,
        }
    }

    fn mul(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
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
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        swanky_error::bail!(
            ErrorKind::UnsupportedError,
            "Projection gates are unsupported"
        )
    }
}

impl Fancy for CircuitAnalyzer {
    type Item = AnalyzerItem;

    fn receive_many(
        &mut self,
        moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
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
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        self.receive_many(moduli, channel)
    }

    fn constant(&mut self, _val: u16, q: u16, _: &mut Channel) -> swanky_error::Result<Self::Item> {
        self.nconstants += 1;
        Ok(AnalyzerItem {
            modulus: q,
            depth: 0,
        })
    }

    fn output(&mut self, x: &Self::Item, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        self.mul_depth = max(self.mul_depth, x.depth);
        Ok(None)
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
        Channel::with(std::io::empty(), |channel| {
            let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
            let x = analyzer_test.bin_encode(x, nbits, channel).unwrap();
            let y = analyzer_test.bin_encode(y, nbits, channel).unwrap();
            let _c = analyzer_test.bin_and(&x, &y, channel);

            assert_eq!(analyzer_test.ninputs, 128);
            assert_eq!(analyzer_test.nands, 64);
            assert_eq!(analyzer_test.nxors, 0);
            assert_eq!(analyzer_test.nconstants, 0);
            assert_eq!(analyzer_test.nnegs, 0);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn binary_addition_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        Channel::with(std::io::empty(), |channel| {
            let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
            let x = analyzer_test.bin_encode(x, nbits, channel).unwrap();
            let y = analyzer_test.bin_encode(y, nbits, channel).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_addition(&x, &y, channel);

            assert_eq!(analyzer_test.ninputs, 128);
            assert_eq!(analyzer_test.nands, 64);
            // There are (nbits -1) adders invoked with a carry
            // and the very first one without. The adders with
            // carry have 3 extra XORs, check fancy_garbling::adder
            // and fancy_garbling::binary_addition for more info
            assert_eq!(analyzer_test.nxors, 64 * 4 - 3);
            assert_eq!(analyzer_test.nconstants, 0);
            assert_eq!(analyzer_test.nnegs, 0);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn binary_multiplication_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        Channel::with(std::io::empty(), |channel| {
            let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
            let x = analyzer_test.bin_encode(x, nbits, channel).unwrap();
            let y = analyzer_test.bin_encode(y, nbits, channel).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_mul(&x, &y, channel);

            // In binary multiplication there are :
            // - 64 * 64 explicit ANDs, i.e. pairwise ANDS between parties input wires.
            // - Sum(65 to 128) binary additions. Recall that in multiplication the input
            //   size grows by 1 bit each round until each 2 times the size of the initial
            //   input (i.e. 64 * 2)
            assert_eq!(analyzer_test.ninputs, 128);
            assert_eq!(analyzer_test.nands, (65..128).sum::<usize>() + 64 * 64);
            assert_eq!(
                analyzer_test.nxors,
                (65..128).sum::<usize>() * 4 - (3 * (128 - 65))
            );
            assert_eq!(analyzer_test.nconstants, 64);
            assert_eq!(analyzer_test.nnegs, 0);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn binary_twos_complement_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        Channel::with(std::io::empty(), |channel| {
            let mut analyzer_test: CircuitAnalyzer = CircuitAnalyzer::new();
            let x = analyzer_test.bin_encode(x, nbits, channel).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_twos_complement(&x, channel);

            assert_eq!(analyzer_test.ninputs, 64);
            assert_eq!(analyzer_test.nands, 63);
            assert_eq!(analyzer_test.nxors, 63 * 4 - 3 + 64 + 2);
            assert_eq!(analyzer_test.nconstants, 64 + 64);
            assert_eq!(analyzer_test.nnegs, 64);
            Ok(())
        })
        .unwrap();
    }
}
