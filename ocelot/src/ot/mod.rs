//! Oblivious transfer traits + instantiations.
//!
//! This module provides traits for standard oblivious transfer (OT), correlated
//! OT, and random OT, alongside implementations of the following OT protocols:
//!
//! * `dummy`: a dummy and completely insecure OT for testing purposes.
//! * `naor_pinkas`: Naor-Pinkas semi-honest OT.
//! * `chou_orlandi`: Chou-Orlandi malicious OT.
//! * `alsz`: Asharov-Lindell-Schneider-Zohner semi-honest OT extension (+ correlated and random OT).
//! * `kos`: Keller-Orsini-Scholl malicious OT extension (+ correlated and random OT).
//!

pub mod alsz;
pub mod explicit_round;
pub mod kos;
pub mod kos_delta;
pub use swanky_ot_noar_pinkas as naor_pinkas;

pub use swanky_ot_chou_orlandi as chou_orlandi;
pub use swanky_ot_traits::*;
/// Instantiation of the Chou-Orlandi OT sender.
pub type ChouOrlandiSender = swanky_ot_chou_orlandi::Sender;
/// Instantiation of the Chou-Orlandi OT receiver.
pub type ChouOrlandiReceiver = swanky_ot_chou_orlandi::Receiver;
/// Instantiation of the dummy OT sender.
pub type DummySender = swanky_ot_dummy::Sender;
/// Instantiation of the dummy OT receiver.
pub type DummyReceiver = swanky_ot_dummy::Receiver;
/// Instantiation of the Naor-Pinkas OT sender.
pub type NaorPinkasSender = naor_pinkas::Sender;
/// Instantiation of the Naor-Pinkas OT receiver.
pub type NaorPinkasReceiver = naor_pinkas::Receiver;
/// Instantiation of the ALSZ OT extension sender, using Chou-Orlandi as the base OT.
pub type AlszSender = alsz::Sender;
/// Instantiation of the ALSZ OT extension receiver, using Chou-Orlandi as the base OT.
pub type AlszReceiver = alsz::Receiver;
/// Instantiation of the KOS OT extension sender, using Chou-Orlandi as the base OT.
pub type KosSender = kos::Sender;
/// Instantiation of the KOS OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosReceiver = kos::Receiver;
/// Instantiation of the KOS Delta-OT extension sender, using Chou-Orlandi as the base OT.
pub type KosDeltaSender = kos_delta::Sender;
/// Instantiation of the KOS Delta-OT extension receiver, using Chou-Orlandi as the base OT.
pub type KosDeltaReceiver = kos_delta::Receiver;
