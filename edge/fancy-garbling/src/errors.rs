//! Errors that may be output by this library.

use std::fmt::{self, Display, Formatter};

/// General wire deserialization error
#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum WireDeserializationError {
    /// Deserialization of `WireMod3` failed
    InvalidWireMod3,
    /// Deserialization of `WireModQ` failed
    InvalidWireModQ(ModQDeserializationError),
}

/// `WireModQ` wire deserialization error
#[cfg(feature = "serde")]
#[derive(Debug)]
pub enum ModQDeserializationError {
    /// Modulus must be greater than 1
    BadModulus(u16),

    /// One of the digits is larger than the modulus
    DigitTooLarge {
        /// The invalid digit
        digit: u16,
        /// Modulus of wire
        modulus: u16,
    },

    /// Unexpected number of digits
    InvalidDigitsLength {
        /// Number of digits given
        got: usize,
        /// Number of digits expected (based on modulus)
        needed: usize,
    },
}

////////////////////////////////////////////////////////////////////////////////
// Serialization error
//

#[cfg(feature = "serde")]
impl Display for WireDeserializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WireDeserializationError::InvalidWireMod3 => {
                "deserialization of WireMod3 failed: both lsb and msb cannot be set".fmt(f)
            }
            WireDeserializationError::InvalidWireModQ(e) => {
                write!(f, "deserialization of WireModQ failed: {}", e)
            }
        }
    }
}

#[cfg(feature = "serde")]
impl Display for ModQDeserializationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ModQDeserializationError::BadModulus(modulus) => {
                write!(f, "modulus must be at least 2. Got {}", modulus)
            }
            ModQDeserializationError::DigitTooLarge { digit, modulus } => {
                write!(
                    f,
                    "a digit {} is greater than the modulus ({}) ",
                    digit, modulus
                )
            }
            ModQDeserializationError::InvalidDigitsLength { got, needed } => {
                write!(
                    f,
                    "invalid number of digits. Expected {}, got {}",
                    needed, got
                )
            }
        }
    }
}

/// Errors emitted by the circuit parser.
#[derive(Debug)]
pub enum CircuitParserError {
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// A regular expression parsing error occurred.
    RegexError(regex::Error),
    /// An error occurred parsing an integer.
    ParseIntError,
    /// An error occurred parsing a line.
    ParseLineError(String),
    /// An error occurred parsing a gate type.
    ParseGateError(String),
}

impl Display for CircuitParserError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitParserError::IoError(e) => write!(f, "io error: {}", e),
            CircuitParserError::RegexError(e) => write!(f, "regex error: {}", e),
            CircuitParserError::ParseIntError => write!(f, "unable to parse integer"),
            CircuitParserError::ParseLineError(s) => write!(f, "unable to parse line '{}'", s),
            CircuitParserError::ParseGateError(s) => write!(f, "unable to parse gate '{}'", s),
        }
    }
}

impl From<std::io::Error> for CircuitParserError {
    fn from(e: std::io::Error) -> CircuitParserError {
        CircuitParserError::IoError(e)
    }
}

impl From<regex::Error> for CircuitParserError {
    fn from(e: regex::Error) -> CircuitParserError {
        CircuitParserError::RegexError(e)
    }
}

impl From<std::num::ParseIntError> for CircuitParserError {
    fn from(_: std::num::ParseIntError) -> CircuitParserError {
        CircuitParserError::ParseIntError
    }
}
