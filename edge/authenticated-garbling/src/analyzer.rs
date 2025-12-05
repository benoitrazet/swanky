//! Fancy object to compute the number of gates in a binary circuit.

use fancy_garbling::{Fancy, FancyBinary, FancyInput, FancyReveal, HasModulus, errors::FancyError};

#[derive(Clone, Debug)]
pub struct AnalyzerItem {
    modulus: u16,
}
impl HasModulus for AnalyzerItem {
    fn modulus(&self) -> u16 {
        self.modulus
    }
}

/// Errors thrown by the Fancy computation.
#[derive(Debug)]
pub enum AnalyzerError {
    /// Error from Fancy library.
    Underlying(FancyError),
}

impl From<FancyError> for AnalyzerError {
    fn from(e: FancyError) -> Self {
        AnalyzerError::Underlying(e)
    }
}

impl std::fmt::Display for AnalyzerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Underlying(e) => writeln!(f, "Fancy error: {}", e),
        }
    }
}

/// Fancy Object which computes information about the circuit
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    /// Create a new Analyzer
    pub fn new() -> Analyzer {
        Analyzer {
            ninputs: 0,
            nands: 0,
            nxors: 0,
            nnegs: 0,
            nconstants: 0,
        }
    }
}

impl FancyInput for Analyzer {
    type Item = AnalyzerItem;
    type Error = AnalyzerError;

    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.ninputs += moduli.len();
        Ok(moduli
            .iter()
            .map(|q| AnalyzerItem { modulus: *q })
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

impl FancyBinary for Analyzer {
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
    fn test_analyzer() {
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
}
