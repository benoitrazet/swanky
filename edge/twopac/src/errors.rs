/// Errors produced by `twopac`.
#[derive(Debug)]
pub enum Error {
    /// An I/O error has occurred.
    IoError(std::io::Error),
    /// An oblivious transfer error has occurred.
    OtError(swanky_ocelot_error::Error),
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

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::OtError(e) => write!(f, "oblivious transfer error: {}", e),
        }
    }
}
