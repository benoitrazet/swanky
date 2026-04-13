pub mod mac;
pub mod specialization;
pub mod vole;

use swanky_party::party_system;

party_system! {
    pub mod party {
        /// The ZK prover.
        Prover,
        /// The ZK verifier.
        Verifier,
    }
}
