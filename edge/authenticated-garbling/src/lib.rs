#![deny(missing_docs)]
//! Authenticated malicious garbling in the presence of a malicious garbler and evaluator

use swanky_party::party_system;
pub mod evaluator;
pub mod garbler;
pub mod preprocess;
pub mod wire;

party_system! {
    mod ps {
        PartyGarbler,
        PartyEvaluator,
    }
}

