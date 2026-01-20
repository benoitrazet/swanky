//! Types for operating over authenticated bits and their extensions.
//!
//! An authenticated bit $`[b]`$ is of the form $`M = K \oplus b \Delta`$, where
//! $`[b]_{\mathsf{A}} := (M, b)`$ is held by Party A (the "prover") and
//! $`[b]_{\mathsf{B}} := (K, \Delta)`$ is held by Party B (the "verifier"). The
//! same value $`\Delta`$ can be used across multiple authenticated bits.
//!
//! An authenticated bit $`[b]`$ can be viewed as a _commitment_ to the bit
//! $`b`$: the verifier does not know which bit the prover holds until it
//! receives the value $`M`$ from the prover (a.k.a. it's _hiding_), and the
//! prover cannot change the bit (a.k.a. it's _binding_).
//!
//! This crate provides several modules implementing authenticated bits and
//! various extensions:
//! - [`authbits`]: Authenticated bits $`[b]`$.
//! - [`authshares`]: A pair of authenticated bits $`\langle x \rangle :=
//!   ([x_1]_{\mathsf{A}}, [x_2]_{\mathsf{B}})`$ forming a random
//!   (authenticated) secret share (i.e., $`x = x_1 \oplus x_2`$).
//! - [`and_triples`]: Random authenticated AND triples $`(\langle x \rangle,
//!   \langle y \rangle, \langle z \rangle)`$ such that $`x \cdot y = z`$.
#![deny(missing_docs)]

pub mod and_triples;
pub mod authbits;
pub mod authshares;
mod leaky_and_triples;
