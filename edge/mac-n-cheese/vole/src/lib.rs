#![allow(clippy::all)]
pub mod mac;
pub mod specialization;
pub mod vole;

use swanky_party2::party_system;

party_system! {
    pub mod party {
        /// The ZK prover.
        Prover,
        /// The ZK verifier.
        Verifier,
    }
}
