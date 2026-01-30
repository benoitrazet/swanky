use fancy_garbling::{
    FancyError,
    errors::{EvaluatorError, GarblerError},
};

/// Errors produced by `twopac`.
#[derive(Debug)]
pub enum Error {
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// An oblivious transfer error has occurred.
    OtError(swanky_ocelot_error::Error),
    /// The garbler produced an error.
    GarblerError(GarblerError),
    /// The evaluator produced an error.
    EvaluatorError(EvaluatorError),
    /// Processing the garbled circuit produced an error.
    FancyError(FancyError),
}

impl std::error::Error for Error {}

impl From<swanky_ocelot_error::Error> for Error {
    fn from(e: swanky_ocelot_error::Error) -> Error {
        Error::OtError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<EvaluatorError> for Error {
    fn from(e: EvaluatorError) -> Error {
        Error::EvaluatorError(e)
    }
}

impl From<GarblerError> for Error {
    fn from(e: GarblerError) -> Error {
        Error::GarblerError(e)
    }
}

impl From<FancyError> for Error {
    fn from(e: FancyError) -> Error {
        Error::FancyError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::OtError(e) => write!(f, "oblivious transfer error: {}", e),
            Error::EvaluatorError(e) => write!(f, "evaluator error: {}", e),
            Error::GarblerError(e) => write!(f, "garbler error: {}", e),
            Error::FancyError(e) => write!(f, "fancy error: {}", e),
        }
    }
}

impl From<Error> for GarblerError {
    fn from(e: Error) -> GarblerError {
        GarblerError::CommunicationError(e.to_string())
    }
}

impl From<Error> for EvaluatorError {
    fn from(e: Error) -> EvaluatorError {
        EvaluatorError::CommunicationError(e.to_string())
    }
}
