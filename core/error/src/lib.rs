#![deny(missing_docs)]
//! A common error type for Swanky.

use std::{
    backtrace::Backtrace,
    fmt::{Debug, Display},
};

macro_rules! error_kind {
    ($(
        #[doc = $doc:literal]
        $kind:ident
    ),*$(,)?) => {
        /// A list of general categories of Swanky error.
        ///
        /// This list is intended to grow over time and it is not
        /// recommended to exhaustively match against it.
        ///
        /// It is used with the [`Error`] type.
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorKind {
            $(#[doc = $doc] $kind),*
        }
        impl Display for ErrorKind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    match self {
                        $(Self::$kind => $doc),*
                    }
                )
            }
        }
    }
}

error_kind! {
    #[doc = "A network error has occurred"]
    NetworkError,
    #[doc = "A correlation check has failed"]
    CorrelationFailure,
    #[doc = "A serialization error has occurred"]
    SerializationError,
    #[doc = "A filesystem error has occurred"]
    FilesystemError,
    #[doc = "An error that does not fall under any other Swanky error kind has occurred"]
    OtherError,
}

struct ErrorInner {
    kind: ErrorKind,
    backtrace: Backtrace,
    message: String,
    context: Vec<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

/// The error type for Swanky operations.
///
/// Errors can be constructed from scratch using [`Error::new`];
/// additional context can be provided to an error at any time with
/// [`context`][Error::context].
/// Use [`kind`][Error::kind] to inspect the [`ErrorKind`] of the
/// `Error`.
pub struct Error {
    inner: Box<ErrorInner>,
}

impl Error {
    /// Construct a new `Error` given an [`ErrorKind`], a message, and
    /// (optionally) a source error.
    #[track_caller]
    pub fn new(
        kind: ErrorKind,
        message: String,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Error {
            inner: Box::new(ErrorInner {
                kind,
                backtrace: Backtrace::capture(),
                message,
                context: Vec::new(),
                source,
            }),
        }
    }

    /// Provide additional context to an `Error`.
    pub fn context(mut self, context_message: String) -> Self {
        self.inner.context.push(context_message);
        self
    }

    /// Returns the corresponding [`ErrorKind`] for this error.
    ///
    /// It is recommended that you only `match` against the
    /// relevant `ErrorKind`s, and match against all others with `_`
    /// (as `ErrorKind` may be extended in the future).
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }
}

/// `Result<T, Error>`
///
/// This can be used anywhere Swanky produces an error.
pub type Result<T> = std::result::Result<T, Error>;

#[test]
fn test_error_sizes() {
    assert_eq!(
        std::mem::size_of::<Error>(),
        std::mem::size_of::<*const ()>()
    );
    assert_eq!(
        std::mem::size_of::<Result<()>>(),
        std::mem::size_of::<*const ()>()
    );
}
