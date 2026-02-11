//! Errors produced by the private set intersection protocols.
#[derive(Debug)]
/// Errors produced by the private set intersection protocols.
pub enum Error {
    /// Coin tossing failed.
    CoinTossError(swanky_cointoss::Error),
    /// The underlying oblivious PRF failed.
    OprfError(swanky_ocelot_error::Error),
    /// An input/output error occurred.
    IoError(std::io::Error),
    /// The cuckoo hash is full.
    CuckooHashFull,
    /// The provided cuckoo hash set size is invalid.
    InvalidCuckooSetSize(usize),
    /// The provided cuckoo hash parameters are invalid.
    InvalidCuckooParameters {
        /// Number of items.
        nitems: usize,
        /// Number of hashes.
        nhashes: usize,
    },
    /// An error occurred in the PSI protocol.
    PsiProtocolError(String),
    /// Not enough payloads.
    InvalidPayloadsLength,
    /// AES GCM Error
    AESGCMError(aes_gcm::Error),
    /// The set of payloads is not equal to the set of keys.
    PayloadSetNotComplete {
        /// length of the set of payloads
        npayloads: usize,
        /// length of the set of primary keys
        nprimarykeys: usize,
    },
    /// An error coming from `eyre`.
    EyreError(eyre::Error),
}

impl From<aes_gcm::Error> for Error {
    #[inline]
    fn from(e: aes_gcm::Error) -> Error {
        Error::AESGCMError(e)
    }
}

impl From<std::io::Error> for Error {
    #[inline]
    fn from(e: std::io::Error) -> Error {
        Error::IoError(e)
    }
}

impl From<swanky_ocelot_error::Error> for Error {
    #[inline]
    fn from(e: swanky_ocelot_error::Error) -> Error {
        Error::OprfError(e)
    }
}

impl From<swanky_cointoss::Error> for Error {
    #[inline]
    fn from(e: swanky_cointoss::Error) -> Error {
        Error::CoinTossError(e)
    }
}

impl From<eyre::Error> for Error {
    fn from(e: eyre::Error) -> Self {
        Error::EyreError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::CoinTossError(e) => write!(f, "coin toss error: {}", e),
            Error::OprfError(e) => write!(f, "oblivious PRF error: {}", e),
            Error::IoError(e) => write!(f, "IO error: {}", e),
            Error::CuckooHashFull => write!(f, "cuckoo hash error: table is full"),
            Error::InvalidCuckooSetSize(n) => {
                write!(f, "cuckoo hash error: invalid set size {}", n)
            }
            Error::InvalidCuckooParameters { nitems, nhashes } => write!(
                f,
                "cuckoo hash error: no parameters set for {} items and {} hashes",
                nitems, nhashes
            ),
            Error::PsiProtocolError(s) => write!(f, "PSI protocol error: {}", s),
            Error::InvalidPayloadsLength => write!(f, "Invalid length of payloads!"),
            Error::AESGCMError(e) => write!(f, "AES GCM Error: {}", e),
            Error::PayloadSetNotComplete {
                npayloads,
                nprimarykeys,
            } => write!(
                f,
                "The set of payloads (len: {}) is not equal to the set of primary keys (len: {})!",
                npayloads, nprimarykeys
            ),
            Error::EyreError(e) => write!(f, "{}", e.to_string()),
        }
    }
}
