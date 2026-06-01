//! Functions for parsing and running circuit files.
//!
//! This module provides parsers for two Bristol circuit formats:
//!
//! - **Bristol Format**: The original format:
//!   <https://nigelsmart.github.io/MPC-Circuits/old-circuits.html>
//! - **Bristol Fashion**: The new format: <https://nigelsmart.github.io/MPC-Circuits>

use crate::circuit::{BinaryCircuit, BinaryGate};
use regex::{Captures, Regex};
use std::{io::BufRead, str::FromStr};
use swanky_error::{ErrorKind, Result, WrapErr, ensure, swanky_error};

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
    /// must follow the Bristol Fashion format.
    pub fn parse_bristol_fashion(mut reader: impl BufRead) -> Result<Self> {
        // Parse first line: "ngates nwires\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let parts = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            parts.len() == 2,
            ErrorKind::OtherError,
            "Failed to parse gate and wire count"
        );
        let ngates = FromStr::from_str(parts[0])
            .wrap_err(ErrorKind::OtherError, "Failed to parse gate count")?;
        let nwires: usize = FromStr::from_str(parts[1])
            .wrap_err(ErrorKind::OtherError, "Failed to parse wire count")?;

        // Parse second line: "ninputs input1 input2 ...\n".
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let parts = line.split_whitespace().collect::<Vec<_>>();
        ensure!(!parts.is_empty(), ErrorKind::OtherError, "Empty input line");

        let ninputs: usize = FromStr::from_str(parts[0])
            .wrap_err(ErrorKind::OtherError, "Failed to parse number of parties")?;
        ensure!(
            parts.len() == ninputs + 1,
            ErrorKind::OtherError,
            "Expected {} input values, got {}",
            ninputs,
            parts.len() - 1
        );
        let mut ninputs_total = 0;
        for part in parts.iter().skip(1) {
            let ninputs: usize = FromStr::from_str(part)
                .wrap_err(ErrorKind::OtherError, "Failed to parse input count")?;
            ninputs_total += ninputs;
        }

        // Parse third line: nparties_output output_bits_party1 output_bits_party2 ...\n
        // Note: nparties_output can be different from nparties (input parties)
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .wrap_err(ErrorKind::OtherError, "Failed to read line")?;
        let parts = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            !parts.is_empty(),
            ErrorKind::OtherError,
            "Empty output line"
        );
        let noutputs: usize = FromStr::from_str(parts[0]).wrap_err(
            ErrorKind::OtherError,
            "Failed to parse number of output parties",
        )?;
        ensure!(
            parts.len() == noutputs + 1,
            ErrorKind::OtherError,
            "Expected {} output values, got {}",
            noutputs,
            parts.len() - 1
        );
        let mut noutputs_total = 0;
        for part in parts.iter().skip(1) {
            let noutputs: usize = FromStr::from_str(part)
                .wrap_err(ErrorKind::OtherError, "Failed to parse output count")?;
            noutputs_total += noutputs;
        }

        let mut circ = Self::new(Some(ngates));

        let re1 = Regex::new(r"1 1 (\d+) (\d+) INV").expect("regex should be valid");
        let re2 = Regex::new(r"2 1 (\d+) (\d+) (\d+) ((AND|XOR))").expect("regex should be valid");

        let mut id = 0;

        // Process inputs.
        for i in 0..ninputs_total {
            circ.gates.push(BinaryGate::Input { id: i });
            circ.input_refs.push(i);
        }
        // Create a constant wire for negations.
        circ.gates.push(BinaryGate::Constant { val: 1 });
        circ.const_refs.push(ninputs_total);
        // Process outputs.
        for i in (0..noutputs_total).rev() {
            circ.output_refs.push(nwires - noutputs_total + i);
        }

        // Parse gate definitions (same as Bristol Format).
        for line in reader.lines() {
            let line = line.wrap_err(ErrorKind::OtherError, "Failed to read line")?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.chars().next() {
                Some('1') => {
                    let cap = regex2captures(&re1, line)?;
                    let yref = cap2int(&cap, 1)?;
                    let out = cap2int(&cap, 2)?;
                    circ.gates.push(BinaryGate::Inv {
                        xref: yref,
                        out: Some(out),
                    })
                }
                Some('2') => {
                    let cap = regex2captures(&re2, line)?;
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
                    swanky_error::bail!(ErrorKind::OtherError, "Invalid gate definition: {}", line);
                }
            }
        }
        Ok(circ)
    }

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
    use crate::circuit::{BinaryCircuit, BinaryGate};
    use std::io::Cursor;

    #[test]
    fn bristol_format_parser_works() {
        // Tests all the circuits in the `circuits/bristol-format` directory.

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-format/adder_32bit.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-format/AES-non-expanded.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-format/sha-1.txt"),
        ));
        assert!(result.is_ok());

        let result = BinaryCircuit::parse_bristol_format(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-format/sha-256.txt"),
        ));
        assert!(result.is_ok());
    }

    #[test]
    fn bristol_fashion_parser_works() {
        // Tests all the circuits in the `circuits/bristol-fashion` directory.

        // Test AES-128 circuit.
        let result = BinaryCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-fashion/aes_128.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // AES-128: 2 input values with 128 bits each = 256 inputs total.
        assert_eq!(circuit.input_refs.len(), 256);
        // AES-128: 1 output value with 128 bits output = 128 outputs total.
        assert_eq!(circuit.output_refs.len(), 128);
        // Verify circuit has gates.
        assert!(!circuit.gates.is_empty());
        // First 256 gates should be inputs.
        for i in 0..256 {
            if let BinaryGate::Input { id } = circuit.gates[i] {
                assert_eq!(id, i);
            } else {
                panic!("Expected Input gate at position {}", i);
            }
        }

        // Test SHA-256 circuit.
        let result = BinaryCircuit::parse_bristol_fashion(Cursor::<&'static [u8]>::new(
            include_bytes!("../circuits/bristol-fashion/sha256.txt"),
        ));
        assert!(result.is_ok());
        let circuit = result.unwrap();
        // SHA-256: 2 parties with 512 + 256 = 768 inputs total
        assert_eq!(circuit.input_refs.len(), 768);
        // SHA-256: 1 party with 256 bits output = 256 outputs total
        assert_eq!(circuit.output_refs.len(), 256);
        // Verify circuit has gates
        assert!(!circuit.gates.is_empty());
    }
}
