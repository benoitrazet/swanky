//! Oblivious PRF traits + instantiations.

pub use swanky_oprf_kkrt as kkrt;
pub mod kmprt;

/// KKRT oblivious PRF sender using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtSender = kkrt::Sender;
/// KKRT oblivious PRF receiver using ALSZ OT extension with Chou-Orlandi as the base OT.
pub type KkrtReceiver = kkrt::Receiver;
/// KMPRT hash-based OPPRF sender, using KKRT as the underlying OPRF.
pub type KmprtSender = kmprt::Sender;
/// KMPRT hash-based OPPRF receiver, using KKRT as the underlying OPRF.
pub type KmprtReceiver = kmprt::Receiver;

pub use swanky_oprf_traits::*;
