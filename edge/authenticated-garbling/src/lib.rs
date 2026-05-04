#![deny(missing_docs)]
//! Authenticated malicious garbling in the presence of a malicious garbler and evaluator

use swanky_party::party_system;

pub mod evaluator;
pub mod garbler;
pub mod preprocesser;
mod tests;
mod wire;
pub use wire::AuthenticatedWireMod2;

party_system! {
    mod ps {
        PartyGarbler,
        PartyEvaluator,
    }
}
