//! Oblivious PRF traits + instantiations.

pub mod kkrt;
pub mod kmprt;
mod prc;

use crate::ot;

/// KKRT oblivious PRF sender using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtSender = kkrt::Sender<ot::AlszReceiver>;
/// KKRT oblivious PRF receiver using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtReceiver = kkrt::Receiver<ot::AlszSender>;
/// KMPRT hash-based OPPRF sender, using KKRT as the underlying OPRF.
pub type KmprtSender = kmprt::Sender<KkrtSender>;
/// KMPRT hash-based OPPRF receiver, using KKRT as the underlying OPRF.
pub type KmprtReceiver = kmprt::Receiver<KkrtReceiver>;

pub use swanky_oprf_traits::*;
