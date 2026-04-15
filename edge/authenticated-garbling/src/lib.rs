#![deny(missing_docs)]
//! Authenticated malicious garbling in the presence of a malicious garbler and evaluator

use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_party::party_system;
use vectoreyes::{SimdBase, U8x16};

pub mod evaluator;
pub mod finalizer;
pub mod garbler;
pub mod preprocesser;
pub mod wire;
pub mod unifier;
mod tests;

/// Mux over bit: if the bit is 0, returns value0, otherwise value1
pub fn mux(bit: F2, value0: U8x16, value1: U8x16) -> U8x16 {
    if bit == F2::ONE { value1 } else { value0 }
}

party_system! {
    mod ps {
        PartyGarbler,
        PartyEvaluator,
    }
}

