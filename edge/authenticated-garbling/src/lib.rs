//! Authenticated garbling for maliciously secure two-party computation.
#![deny(missing_docs)]

mod evaluator;
pub use evaluator::{EvaluatorOffline, EvaluatorOnline, EvaluatorValidator};
mod garbler;
pub use garbler::{GarblerOffline, GarblerOnline, GarblerOutput, GarblerValidator};
mod preprocesser;
pub use preprocesser::WirePreProcessor;
mod wire;
pub use wire::AuthenticatedWireMod2;
mod vec_wrapper;

// Party system type aliases for the garbler and evaluator
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
