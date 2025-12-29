//! Fancy object to compute the number of gates in a binary circuit.
use eyre::{ErrReport, eyre};
use fancy_garbling::{Fancy, FancyBinary, FancyInput, FancyReveal, HasModulus, errors::FancyError};
#[derive(Clone, Debug)]
/// "An instantiation of [FancyInput::Item] used by [Analyzer]."
///
/// A dummy FancyItem which is returned when profiling a [`fancy_garbling::Fancy`] circuit.
/// The [`AnalyzerItem`] only contains the wire modulus. This is because
/// [`fancy_garbling::Fancy::Item`] need to implement [`HasModulus`].
pub struct AnalyzerItem {
    modulus: u16,
}
impl HasModulus for AnalyzerItem {
    // Returns the modulus of the current wire.
    // Since [`Analyzer`] is only defined for binary
    // circuits, for now, the modulus should always be 2.
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

#[derive(Debug)]
/// Error from the [`Analyzer`] fancy object
///
/// This error wraps any underlying error thrown by
/// [`fancy_garbling::Fancy`] with eyre.
pub enum AnalyzerError {
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
            Self::Underlying(e) => writeln!(f, "Fancy error: {}", e),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// A [`fancy_garbling::Fancy`] object which counts gates in a binary circuit.
///
/// Specifically, [`Analyzer`] stores the number of inputs,
/// ands, xors, negations and constants in the circuits. This
/// information is especially useful for pre-processing authenticated
/// garbling circuits.
pub struct Analyzer {
    ninputs: usize,
    nands: usize,
    nxors: usize,
    nnegs: usize,
    nconstants: usize,
}

impl std::fmt::Display for Analyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "computation info:")?;
        writeln!(f, "  number of inputs:             {:16}", self.ninputs)?;
        writeln!(f, "  number of ands:             {:16}", self.nands)?;
        writeln!(f, "  number of xors:             {:16}", self.nxors)?;
        writeln!(f, "  number of negations:             {:16}", self.nnegs)?;
        writeln!(
            f,
            "  number of constants:             {:16}",
            self.nconstants
        )?;
        Ok(())
    }
}

impl Analyzer {
    /// Create a new [`Analyzer`] and sets all the gate
    /// counts to 0.
    pub fn new() -> Analyzer {
        Analyzer {
            ninputs: 0,
            nands: 0,
            nxors: 0,
            nnegs: 0,
            nconstants: 0,
        }
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

impl FancyInput for Analyzer {
    type Item = AnalyzerItem;
    type Error = AnalyzerError;
    /// Receive the other party's garbled inputs. Because [`Analyzer`] does not actually
    /// perform the circuit computation and instead just analyzes the structure of the circuit,
    /// this function does not incur any communication costs, i.e. no OT is invoked here.
    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.ninputs += moduli.len();
        Ok(moduli
            .iter()
            .map(|q| AnalyzerItem { modulus: *q })
            .collect())
    }
    /// Encode the current party's garbled inputs. Because [`Analyzer`] does not actually
    /// perform the circuit computation and instead just analyzes the structure of the circuit,
    /// this function does not incur any communication costs, i.e. no OT is invoked here.
    fn encode_many(
        &mut self,
        _values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error> {
        self.receive_many(moduli)
    }
}

/// [`Analyzer`] is only implemented for now for [`fancy_garbling::FancyBinary`]
///
/// Each [`fancy_garbling::FancyBinary`] operation is translated to the number of
/// underlying "basic" gates which constitute it. For example, [`fancy_garbling::FancyBinary::xor`]
/// is a single XOR gate, while [`fancy_garbling::FancyBinary::adder`] is made up of
/// 5 XOR gates and 2 AND gates. These numbers are directly taken from [`fancy_garbling::FancyBinary`].
///
/// Note 1: The 3 "basic" gates are XOR, AND, NEG, while the 2 "basic" input gates are the
/// input wires and the constant gates.
///
/// Note 2: The more complex functions found in [`fancy_garbling::BinaryGadgets`] all
/// use these basic building blocks and that [`Analyzer`] will hence provide these counts for them
/// as well.
///
/// Note 3: Again recall that [`Analyzer`] will not perform the actual circuit computation and will
/// instead only count the number of "basic" gates and return the dummy item [`AnalyzerItem`]
impl FancyBinary for Analyzer {
    ///
    fn xor(&mut self, x: &Self::Item, _y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nxors += 1;
        Ok(AnalyzerItem { modulus: x.modulus })
    }

    fn and(&mut self, x: &Self::Item, _y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        Ok(AnalyzerItem { modulus: x.modulus })
    }
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nnegs += 1;
        Ok(AnalyzerItem { modulus: x.modulus })
    }
    fn or(&mut self, x: &Self::Item, _y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        self.nnegs += 3;
        Ok(AnalyzerItem { modulus: x.modulus })
    }
    fn adder(
        &mut self,
        x: &Self::Item,
        _y: &Self::Item,
        _carry_in: Option<&Self::Item>,
    ) -> Result<(Self::Item, Self::Item), Self::Error> {
        self.nands += 2;
        self.nxors += 5;
        Ok((
            AnalyzerItem { modulus: x.modulus },
            AnalyzerItem { modulus: x.modulus },
        ))
    }
    fn and_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        self.nands += args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
        })
    }
    fn or_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        self.nands += args.len();
        self.nnegs += 3 * args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
        })
    }
    fn xor_many(&mut self, args: &[Self::Item]) -> Result<Self::Item, Self::Error> {
        self.nxors += args.len();
        Ok(AnalyzerItem {
            modulus: args[0].modulus,
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
        Ok(AnalyzerItem { modulus: x.modulus })
    }
    fn mux(
        &mut self,
        _b: &Self::Item,
        x: &Self::Item,
        _y: &Self::Item,
    ) -> Result<Self::Item, Self::Error> {
        self.nands += 1;
        self.nxors += 2;
        Ok(AnalyzerItem { modulus: x.modulus })
    }
}

impl Fancy for Analyzer {
    type Item = AnalyzerItem;
    type Error = AnalyzerError;

    fn constant(&mut self, _val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.nconstants += 1;
        Ok(AnalyzerItem { modulus: q })
    }

    fn output(&mut self, _x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        Ok(None)
    }
}

impl FancyReveal for Analyzer {
    fn reveal(&mut self, _x: &Self::Item) -> Result<u16, Self::Error> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fancy_garbling::BinaryGadgets;
    #[test]
    fn single_and_gate_count_is_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: Analyzer = Analyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            let y = analyzer_test.bin_encode(y, nbits).unwrap();
            let _c = analyzer_test.bin_and(&x, &y);
        }
        let analyzer_correct = Analyzer {
            ninputs: 128,
            nands: 64,
            nxors: 0,
            nnegs: 0,
            nconstants: 0,
        };
        assert_eq!(analyzer_test, analyzer_correct);
    }
    #[test]
    fn binary_addition_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: Analyzer = Analyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            let y = analyzer_test.bin_encode(y, nbits).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_addition(&x, &y);
        }

        let analyzer_correct = Analyzer {
            ninputs: 128,
            // number of ands in an adder
            nands: 64 * 2,
            // number of xors in an adder
            nxors: 64 * 5,
            nnegs: 0,
            nconstants: 0,
        };
        assert_eq!(analyzer_test, analyzer_correct);
    }
    #[test]
    fn binary_multiplication_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let y = 0;
        let mut analyzer_test: Analyzer = Analyzer::new();
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
        let analyzer_correct = Analyzer {
            ninputs: 128,
            nands: (65..128).sum::<usize>() * 2 + 64 * 64,
            nxors: (65..128).sum::<usize>() * 5,
            nnegs: 0,
            nconstants: 64,
        };
        assert_eq!(analyzer_test, analyzer_correct);
    }
    #[test]
    fn binady_twos_complement_counts_are_correct() {
        let nbits = 64;
        let x = 0;
        let mut analyzer_test: Analyzer = Analyzer::new();
        {
            let x = analyzer_test.bin_encode(x, nbits).unwrap();
            // bin_addition is equivalent to an "adder" per wire
            let _c = analyzer_test.bin_twos_complement(&x);
        }

        let analyzer_correct = Analyzer {
            ninputs: 64,
            nands: 63 * 2,
            nxors: 63 * 5 + 3,
            nnegs: 64,
            nconstants: 64,
        };
        assert_eq!(analyzer_test, analyzer_correct);
    }
}
