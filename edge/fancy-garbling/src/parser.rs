//! Functions for parsing and running a circuit file.

use crate::circuit::{BinaryCircuit, BinaryGate};
use regex::{Captures, Regex};
use std::{io::BufRead, str::FromStr};
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
    /// Generates a new [`BinaryCircuit`] from the provided [`BufRead`]er. The file
    /// must follow the Bristol Format given here:
    /// <https://nigelsmart.github.io/MPC-Circuits/old-circuits.html>.
    pub fn parse_bristol_format(mut reader: impl BufRead) -> Result<Self> {
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

        // Process inputs.
        for i in 0..n1 + n2 {
            circ.gates.push(BinaryGate::Input { id: i });
            circ.input_refs.push(i);
        }
        // Create a constant wire for negations.
        // This is no longer required for the implementation
        // of our garbler/evaluator pair. Consider removing
        circ.gates.push(BinaryGate::Constant { val: 1 });
        circ.const_refs.push(n1 + n2);
        // Process outputs.
        for i in 0..n3 {
            circ.output_refs.push(nwires - n3 + i);
        }
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, &line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
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
    use crate::circuit::BinaryCircuit;
    use std::io::Cursor;

    #[test]
    fn bristol_format_parser_works() {
        // Tests all the circuits in the `circuits` directory.

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/adder_32bit.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/AES-non-expanded.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/sha-1.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/sha-256.txt"),
        ));
        assert!(result.is_ok());
    }
}
