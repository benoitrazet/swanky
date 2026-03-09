#![allow(clippy::all)]
//! Humidor is an implementation of the Ligero ZK protocol:
//! <https://dl.acm.org/doi/pdf/10.1145/3133956.3134104>
//!
//! # Security Warning
//! Humidor currently suffers from several vulnerabilities, as documented in
//! Issues [#39](https://github.com/GaloisInc/swanky/issues/39),
//! [#40](https://github.com/GaloisInc/swanky/issues/40), and
//! [#41](https://github.com/GaloisInc/swanky/issues/41) on GitHub. Until those
//! are fixed it is best to not use this code!

#![deny(missing_docs)]

pub mod ligero;
mod merkle;
mod params;
mod security_warning;
mod threshold_secret_sharing;
mod util;
