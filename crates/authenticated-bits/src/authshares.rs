//! Authenticated shares.
//!
//! See [`crate`] for a high-level description of authenticated bits. An
//! authenticated share $`\langle \lambda \rangle = \langle r | s \rangle`$ is a
//! pair of authenticated bits $`[r]_A`$, $`[s]_B`$, where $`[r]_A`$ denotes
//! that $`[r]`$ is an authenticated bit held by Party A, and likewise,
//! $`[s]_B`$ is an authenticated bit held by Party B. We define $`\lambda = r
//! \oplus s`$.
