//! Functions for parsing and running a circuit file based on the format given
//! here: <https://homes.esat.kuleuven.be/~nsmart/MPC/>.

use crate::circuit::{BinaryCircuit, BinaryGate, CircuitRef, CircuitType};
use regex::{Captures, Regex};
use std::str::FromStr;
use swanky_error::{ErrorKind, Result, WrapErr, swanky_error};

enum GateType {
    AndGate,
    XorGate,
}

fn cap2int(cap: &Captures, idx: usize) -> Result<usize> {
    let s = cap
        .get(idx)
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Failed to match index '{idx}'"))?;
    FromStr::from_str(s.as_str())
        .wrap_err(ErrorKind::OtherError, "Failed to convert value to string")
}

fn cap2typ(cap: &Captures, idx: usize) -> Result<GateType> {
    let s = cap
        .get(idx)
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Failed to match index '{idx}'"))?;
    let s = s.as_str();
    match s {
        "AND" => Ok(GateType::AndGate),
        "XOR" => Ok(GateType::XorGate),
        s => swanky_error::bail!(ErrorKind::OtherError, "Unknown gate type '{s}'"),
    }
}

fn regex2captures<'t>(re: &Regex, line: &'t str) -> Result<Captures<'t>> {
    re.captures(line)
        .ok_or_else(|| swanky_error!(ErrorKind::OtherError, "Failed to find match for regex"))
}

impl BinaryCircuit {
    /// Generates a new `Circuit` from file `filename`. The file must follow the
    /// format given here: <https://homes.esat.kuleuven.be/~nsmart/MPC/old-circuits.html>,
    /// (Bristol Format---the OLD format---not Bristol Fashion---the NEW format) otherwise
    /// a `CircuitParserError` is returned.
    pub fn parse(mut reader: impl std::io::BufRead) -> Result<Self> {
        // Parse first line: ngates nwires\n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let re = Regex::new(r"(\d+)\s+(\d+)").expect("regex should be valid");
        let cap = regex2captures(&re, &line)?;
        let ngates = cap2int(&cap, 1)?;
        let nwires = cap2int(&cap, 2)?;

        // Parse second line: n1 n2 n3\n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let re = Regex::new(r"(\d+)\s+(\d+)\s+(\d+)").expect("regex should be valid");
        let cap = regex2captures(&re, &line)?;
        let n1 = cap2int(&cap, 1)?; // Number of garbler inputs
        let n2 = cap2int(&cap, 2)?; // Number of evaluator inputs
        let n3 = cap2int(&cap, 3)?; // Number of outputs

        // Parse third line: \n
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        #[allow(clippy::trivial_regex)]
        let re = Regex::new(r"\n").expect("regex should be valid");
        let _ = regex2captures(&re, &line)?;

        let mut circ = Self::new(Some(ngates));

        let re1 = Regex::new(r"1 1 (\d+) (\d+) INV").expect("regex should be valid");
        let re2 = Regex::new(r"2 1 (\d+) (\d+) (\d+) ((AND|XOR))").expect("regex should be valid");

        let mut id = 0;

        // Process garbler inputs.
        for i in 0..n1 {
            circ.gates.push(BinaryGate::GarblerInput { id: i });
            circ.garbler_input_refs
                .push(CircuitRef { ix: i, modulus: 2 });
        }
        // Process evaluator inputs.
        for i in 0..n2 {
            circ.gates.push(BinaryGate::EvaluatorInput { id: i });
            circ.evaluator_input_refs.push(CircuitRef {
                ix: n1 + i,
                modulus: 2,
            });
        }
        // Create a constant wire for negations.
        // This is no longer required for the implementation
        // of our garbler/evaluator pair. Consider removing
        circ.gates.push(BinaryGate::Constant { val: 1 });
        let oneref = CircuitRef {
            ix: n1 + n2,
            modulus: 2,
        };
        circ.const_refs.push(oneref);
        // Process outputs.
        for i in 0..n3 {
            circ.output_refs.push(CircuitRef {
                ix: nwires - n3 + i,
                modulus: 2,
            });
        }
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, &line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    circ.gates.push(BinaryGate::Inv {
                        xref: yref,
                        out: Some(out),
                    })
                }
                Some('2') => {
                    let cap = regex2captures(&re2, &line)?;
                    let xref = cap2int(&cap, 1)?;
                    let yref = cap2int(&cap, 2)?;
                    let out = cap2int(&cap, 3)?;
                    let typ = cap2typ(&cap, 4)?;
                    let xref = CircuitRef {
                        ix: xref,
                        modulus: 2,
                    };
                    let yref = CircuitRef {
                        ix: yref,
                        modulus: 2,
                    };
                    let gate = match typ {
                        GateType::AndGate => {
                            let gate = BinaryGate::And {
                                xref,
                                yref,
                                id,
                                out: Some(out),
                            };
                            id += 1;
                            gate
                        }
                        GateType::XorGate => BinaryGate::Xor {
                            xref,
                            yref,
                            out: Some(out),
                        },
                    };
                    circ.gates.push(gate);
                }
                None => break,
                _ => {
                    swanky_error::bail!(ErrorKind::OtherError, "Invalid wire value");
                }
            }
        }
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use swanky_rng::AesRng;

    use crate::{
        WireMod2,
        circuit::{BinaryCircuit as Circuit, eval_plain},
        classic::GarbledCircuit,
    };

    #[test]
    fn test_parser() {
        let circ = Circuit::parse(std::io::Cursor::<&'static [u8]>::new(include_bytes!(
            "../circuits/AES-non-expanded.txt"
        )))
        .unwrap();
        let key = vec![0u16; 128];
        let pt = vec![0u16; 128];
        let output = eval_plain(&circ, &pt, &key).unwrap();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110"
        );
        let key = vec![1u16; 128];
        let pt = vec![0u16; 128];
        let output = eval_plain(&circ, &pt, &key).unwrap();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100"
        );
        let mut key = vec![0u16; 128];
        for key_part in key.iter_mut().take(8) {
            *key_part = 1;
        }
        let pt = vec![0u16; 128];
        let output = eval_plain(&circ, &pt, &key).unwrap();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101"
        );
        let mut key = vec![0u16; 128];
        key[7] = 1;
        let pt = vec![0u16; 128];
        let output = eval_plain(&circ, &pt, &key).unwrap();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110"
        );
    }

    #[test]
    fn test_gc_eval() {
        let circ = Circuit::parse(std::io::Cursor::<&'static [u8]>::new(include_bytes!(
            "../circuits/AES-non-expanded.txt"
        )))
        .unwrap();
        let (en, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(&circ, AesRng::new()).unwrap();
        let gb = en.encode_garbler_inputs(&vec![0u16; 128]);
        let ev = en.encode_evaluator_inputs(&vec![0u16; 128]);
        gc.eval(&circ, &gb, &ev).unwrap();
    }
}
