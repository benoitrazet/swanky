//! Authenticated garbling for maliciously secure two-party computation.
//!
//! This implements the authenticated garbling protocol presented by Katz et
//! al.[^1].
//!
//! References:
//! [^1]: J. Katz, S. Ranellucci, M. Rosulek, X. Wang. "Optimizing Authenticated
//! Garbling for Faster Secure Two-Party Computation".
//! <https://eprint.iacr.org/2018/578.pdf>
#![deny(missing_docs)]

mod evaluator;
pub use evaluator::{EvaluatorOffline, EvaluatorOnline, EvaluatorOutput, EvaluatorValidator};
mod garbler;
pub use garbler::{GarblerOffline, GarblerOnline, GarblerOutput, GarblerValidator};
mod preprocesser;
pub use preprocesser::WirePreProcessor;
mod wire;
pub use wire::EvaluatorWire;
mod vec_wrapper;

swanky_party::party_system! {
    mod ps {
        /// The garbler party.
        PartyGarbler,
        /// The evaluator party.
        PartyEvaluator,
    }
}

pub use ps::{PartyEvaluator, PartyGarbler};

#[cfg(test)]
mod tests;
