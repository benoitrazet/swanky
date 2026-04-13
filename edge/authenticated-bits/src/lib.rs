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
use swanky_field_binary::{F2, F128b};
use vectoreyes::{SimdBase, U8x16};

pub mod and_triples;
pub mod authbits;
pub mod authshares;
mod leaky_and_triples;

/// Extract the least-significant bit from a `F128b` value.
pub fn lsb(input: F128b) -> F2 {
    F2::from((U8x16::from(input).extract::<0>() & 1) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::prelude::*;
    use swanky_field_binary::{F2, F128b};
    use vectoreyes::U8x16;

    proptest! {
        #[test]
        fn lsb_works(input in any::<u128>()) {
            prop_assert_eq!(lsb(F128b::from(U8x16::from(input))), F2::from((input & 1) != 0));
        }
    }
}
