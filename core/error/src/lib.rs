#![deny(missing_docs)]
//! A common error type for Swanky.
//!
//! - [`Error`] is modeled after [`std::io::Error`]
//! - There is an `eyre`-like [`Result<T>`] type alias and set of
//!   corresponding macros (e.g. [`ensure`])
//! - Extension trait [`ResultExt`] allows ad-hoc contextual
//!   information to be added to errors in [`Result<T>`]
//! - Extension trait [`WrapErr`] allows a [`Result<T, E:
//!   std::error::Error>`][std::result::Result] to be converted to a
//!   [`Result<T>`]
//! - Extension trait [`OptionExt`] allows any [`Option<T>`] to be
//!   converted to a [`Result<T>`]

use std::{
    backtrace::Backtrace,
    borrow::Cow,
    fmt::{Arguments, Debug, Display},
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
        /// It is used with the [`Error`] type; note that `core`
        /// Swanky crates should **not** use `ErrorKind::Other`; this
        /// variant is for `edge` crates and downstream consumers of
        /// Swanky to integrate seamlessly with `swanky_error` when
        /// the other variants are insufficient.
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
    #[doc = "An error occurred while initializing an object/protocol"]
    InitializationError,
    #[doc = "An operation that is unsupported was attempted"]
    UnsupportedError,
    #[doc = "An error that does not fall under any other Swanky error kind has occurred"]
    OtherError,
}

struct ErrorInner {
    kind: ErrorKind,
    backtrace: Backtrace,
    message: Cow<'static, str>,
    context: Vec<Cow<'static, str>>,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

fn pretty_context(context: &[Cow<'static, str>]) -> String {
    let mut out = String::new();

    for (i, s) in context.iter().enumerate() {
        out.push_str(&format!("\t{}: {}\n", i, s));
    }

    out
}

impl Debug for ErrorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kind: {:?}", self.kind)?;
        write!(f, "\n\nMessage:\n\t{}", self.message)?;

        if !self.context.is_empty() {
            write!(f, "\n\nContext:\n{}", pretty_context(&self.context))?;
        }

        if let Some(ref cause) = self.source {
            write!(f, "\n\nCaused by:\n\t{}", cause)?;
        }

        if let std::backtrace::BacktraceStatus::Captured = self.backtrace.status() {
            let mut backtrace = self.backtrace.to_string();
            write!(f, "\n\n")?;
            writeln!(f, "Stack backtrace:")?;
            backtrace.truncate(backtrace.trim_end().len());
            write!(f, "{}", backtrace)?;
        }

        Ok(())
    }
}

impl Display for ErrorInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kind: {:?}\nMessage: {}", self.kind, self.message)
    }
}

/// The error type for Swanky operations.
///
/// Errors can be constructed from scratch using [`Error::new`];
/// additional context can be provided to an error at any time with
/// [`context`][Error::context].
/// Use [`kind`][Error::kind] to inspect the [`ErrorKind`] of the
/// `Error`.
///
/// See [`Result`], [`swanky_error`], [`bail`], and [`ensure`] for an
/// `anyhow-`/`eyre`-like API for using this type, and see [`WrapErr`]
/// to integrate standard errors into code using this error type /
/// [`Result`].
pub struct Error {
    inner: Box<ErrorInner>,
}

impl Error {
    /// Construct a new `Error` given an [`ErrorKind`], a message, and
    /// (optionally) a source error.
    ///
    /// It is atypical to use this method directly; see
    /// [`swanky_error`] for construction of ad-hoc errors (e.g. with
    /// no `source`), and [`WrapErr`] which provides methods to
    /// convert `Result<T, E: std::error::Error>` to `Result<T,
    /// Error>`.
    #[track_caller]
    pub fn new(
        kind: ErrorKind,
        message: impl Into<Cow<'static, str>>,
        source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
    ) -> Self {
        Error {
            inner: Box::new(ErrorInner {
                kind,
                backtrace: Backtrace::capture(),
                message: message.into(),
                context: Vec::new(),
                source,
            }),
        }
    }

    /// Provide additional context to an `Error`.
    ///
    /// It is atypical to use this method directly; see
    /// [`ResultExt`] which adds this functionality to [`Result<T>`]
    /// values.
    pub fn context(mut self, context_message: impl Into<Cow<'static, str>>) -> Self {
        self.inner.context.push(context_message.into());
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

    /// Create a new error using the kind and message of another.
    ///
    /// It is atypical to use this method; see [`WrapErr`] which adds
    /// this functionality to [`Result<T, U>`] values.
    pub fn wrap_err(self, other: Self) -> Self {
        Self::new(other.inner.kind, other.inner.message, Some(Box::new(self)))
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Need to temporarily unwrap the `Option` for successful
        // deref coercion.
        if let Some(ref e) = self.inner.source {
            Some(&**e)
        } else {
            None
        }
    }
}

/// An alias for `Result<T, Error>`.
///
/// This can be used anywhere Swanky produces an error.
pub type Result<T> = std::result::Result<T, Error>;

/// Return early with an error if a condition is not satisfied.
///
/// This is equivalent to `if !$cond { bail!(<other args>); }`.
///
/// This is analogous to `assert!`, but returns a [`Result`] rather
/// than panicking if the condition fails.
///
/// ## Example
///
/// ```
/// fn ensure_demo() -> swanky_error::Result<()> {
///     swanky_error::ensure!(
///         2 + 2 == 4,
///         swanky_error::ErrorKind::OtherError,
///         "Uh oh! Expected {}",
///         4,
///     );
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $kind:expr, $msg:literal $(,)?) => {
        if !$condition {
            $crate::bail!($kind, $msg)
        }
    };
    ($condition:expr, $kind:expr, $fmt:expr, $($arg:tt)*) => {
        if !$condition {
            $crate::bail!($kind, $fmt, $($arg)*)
        }
    };
}

/// Return early with an error.
///
/// This is equivalent to `return Err(swanky_err!(<args>))`.
///
/// ## Example
///
/// ```
/// fn bail_demo() -> swanky_error::Result<()> {
///     swanky_error::bail!(
///         swanky_error::ErrorKind::OtherError,
///         "Something went wrong; bailing!",
///     );
/// }
/// ```
#[macro_export]
macro_rules! bail {
    ($kind:expr, $msg:literal) => {
        return Err($crate::swanky_error!($kind, $msg))
    };
    ($kind:expr, $fmt:expr, $($arg:tt)*) => {
        return Err($crate::swanky_error!($kind, $fmt, $($arg)*))
    };
}

// Public to support macros; not intended for direct use.
//
// Helps our macros work correctly with both string literals and
// format strings.
#[inline]
#[cold]
#[doc(hidden)]
pub fn format_err(kind: ErrorKind, args: Arguments) -> Error {
    if let Some(message) = args.as_str() {
        Error::new(kind, message, None)
    } else {
        Error::new(kind, std::fmt::format(args), None)
    }
}

/// Construct an ad-hoc error from an [`ErrorKind`] and string/format
/// string with arguments; this evaluates to an [`Error`].
///
/// ## Example
///
/// ```
/// fn swanky_error_demo() -> swanky_error::Result<()> {
///     let e = swanky_error::swanky_error!(swanky_error::ErrorKind::OtherError, "Oops!");
///     // ... Other things ...
///
///     // ... If you need to return the error in a `Result` ...
///     Err(e)
/// }
/// ```
#[macro_export]
macro_rules! swanky_error {
    ($kind:expr, $msg:literal $(,)?) => {
        $crate::format_err($kind, std::format_args!($msg))
    };
    ($kind:expr, $fmt:expr, $($arg:tt)*) => {
        $crate::Error::new($kind, std::format!($fmt, $($arg)*), None)
    };
}

mod sealed {
    pub trait Sealed {}
    impl<T, E> Sealed for std::result::Result<T, E> {}
    impl<T> Sealed for Option<T> {}
}
use sealed::Sealed;

/// Provides the [`context`][ResultExt::context] method for
/// [`Result<T>`].
///
/// This trait is sealed and cannot be implemented for types outside
/// of `swanky_error`.
pub trait ResultExt<T>: Sealed {
    /// Provide additional context to the error value.
    ///
    /// Prefer [`ResultExt::with_context`], unless the `msg` value
    /// already exists.
    fn context(self, msg: impl Into<Cow<'static, str>>) -> Result<T>;

    /// Provide additional context to the error value, evaluating the
    /// context lazily only once an error does occur.
    ///
    /// If the closure returns an already-constructed `String` value,
    /// see [`ResultExt::context`].
    fn with_context<S>(self, f: impl FnOnce() -> S) -> Result<T>
    where
        S: Into<Cow<'static, str>>;
}

impl<T> ResultExt<T> for Result<T> {
    #[inline]
    fn context(self, msg: impl Into<Cow<'static, str>>) -> Result<T> {
        self.map_err(|e| e.context(msg))
    }
    #[inline]
    fn with_context<S>(self, f: impl FnOnce() -> S) -> Result<T>
    where
        S: Into<Cow<'static, str>>,
    {
        self.map_err(|e| e.context(f()))
    }
}

/// Provides the [`wrap_err`][WrapErr::wrap_err] method for [`Result<T,
/// E: std::error::Error>`][std::result::Result].
///
/// This trait is sealed and cannot be implemented for types outside
/// of `swanky_error`.
pub trait WrapErr: Sealed {
    /// The type of a successful computation, (i.e. the type of `x`
    /// when  `self` is `Ok(x)`).
    type Output;

    /// Wrap the error value with a new [`Error`], using this error as
    /// its `source`.
    ///
    /// Prefer [`WrapErr::wrap_err_with`], unless the `msg` value
    /// already exists.
    fn wrap_err(self, kind: ErrorKind, msg: impl Into<Cow<'static, str>>) -> Result<Self::Output>;

    /// Lazily wrap the error value with a new [`Error`], constructing
    /// the message only once an error does occur.
    ///
    /// If the closure returns an already-constructed `String` value,
    /// see [`WrapErr::wrap_err`].
    fn wrap_err_with<S>(self, kind: ErrorKind, f: impl FnOnce() -> S) -> Result<Self::Output>
    where
        S: Into<Cow<'static, str>>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> WrapErr for std::result::Result<T, E> {
    type Output = T;

    #[inline]
    fn wrap_err(self, kind: ErrorKind, msg: impl Into<Cow<'static, str>>) -> Result<Self::Output> {
        self.map_err(|e| Error::new(kind, msg, Some(Box::new(e))))
    }

    #[inline]
    fn wrap_err_with<S>(self, kind: ErrorKind, f: impl FnOnce() -> S) -> Result<Self::Output>
    where
        S: Into<Cow<'static, str>>,
    {
        self.map_err(|e| Error::new(kind, f(), Some(Box::new(e))))
    }
}

/// Provides the [`ok_or_swanky_error`][OptionExt::ok_or_swanky_error]
/// method for [`Option<T>`].
///
/// This trait is sealed and cannot be implemented for types outside
/// of `swanky_error`.
pub trait OptionExt<T>: Sealed {
    /// Transform the [`Option<T>`] into a [`Result<T>`], mapping
    /// `Some(v)` to `Ok(v)` and `None` to a new [`Error`].
    fn ok_or_swanky_error(
        self,
        kind: ErrorKind,
        message: impl Into<Cow<'static, str>>,
    ) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    #[inline]
    #[track_caller]
    fn ok_or_swanky_error(
        self,
        kind: ErrorKind,
        message: impl Into<Cow<'static, str>>,
    ) -> Result<T> {
        match self {
            Some(ok) => Ok(ok),
            None => Err(Error::new(kind, message, None)),
        }
    }
}

// This test guarantees that `Error` (and `Result`s over `Error`) are
// the same size as a raw pointer (e.g. as small as reasonably
// possible).
//
// This is important to minimizing the impact of Swanky errors on
// program performance, particularly memory usage.
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

#[test]
fn test_swanky_error() {
    let mut e = swanky_error!(ErrorKind::OtherError, "Message");
    e = e.context("Context".to_string());

    assert_eq!(e.inner.kind, ErrorKind::OtherError);
    assert_eq!(e.inner.message, "Message");
    assert_eq!(e.inner.context, vec!["Context"]);
}

#[test]
fn test_bail() {
    fn bails() -> Result<()> {
        bail!(ErrorKind::OtherError, "Get me out of here!")
    }

    assert!(bails().is_err());
}

#[test]
fn test_ensure() {
    fn ensure_true() -> Result<()> {
        ensure!(true, ErrorKind::OtherError, "A happy universe.");
        Ok(())
    }

    assert!(ensure_true().is_ok());

    fn ensure_false() -> Result<()> {
        ensure!(false, ErrorKind::OtherError, "A sad universe.");
        Ok(())
    }

    assert!(ensure_false().is_err());
}
