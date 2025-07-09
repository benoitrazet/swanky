#![deny(missing_docs)]
//! 128-, 256- and 512-bit blocks of data.

/// A 128-bit block of data.
///
/// **NOTE:** This is a legacy type alias, and may be removed in the future.
/// New code should prefer direct uses of [`vectoreyes::U8x16`].
pub type Block = vectoreyes::U8x16;

mod block256;
pub use block256::Block256;

mod block512;
pub use block512::Block512;
