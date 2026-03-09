//! Utilities to map between party systems
//!
//! When implementing a cryptographic protocol, you might need to invoke a subprotocol. For
//! instance, a garbled circuit protocol might need to invoke an oblivious transfer protocol as a
//! subroutine.
//!
//! ```
//! # use swanky_party::{*, private::*, either::*, party_map::*};
//! // We define parties for oblivious transfer.
//! party_system! {
//!     mod ot {
//!         Sender,
//!         Receiver,
//!     }
//! }
//! // And now we define parties for garbled circuits.
//! party_system! {
//!     mod gc {
//!         Garbler,
//!         Evaluator,
//!     }
//! }
//! // This isn't the real OT trait; it also doesn't use network communication. It just serves as
//! // an example.
//! pub trait OT<P: ot::Party>: Sized {
//!     fn init() -> Self;
//!     fn random_ot(
//!         self,
//!         choices: &[PartyPrivate<ot::Receiver, P, bool>],
//!     ) -> (
//!         Self,
//!         Vec<PartyEither<P, [u128; 2], u128>>,
//!     );
//! }
//! ```
//! Now that we have this setup, what happens if we go to define some garbled circuits code:
//!
//! ```compile_fail
//! struct MyGarbledCircuit<P: gc::Party, OtProtocol: OT</* what goes here? */>> {
//!     ot: OtProtocol,
//!     phantom: std::marker::PhantomData<P>,
//! }
//! ```
//!
//! We need a way to come up with an `ot::Party` that corresponds to the role that the OT protocol
//! plays in our GC protocol. That's the job of [`PartyMap`].
//!
//! `PartyMap<P, P0, P1> == P0` if `P` is `Party0`, and `P1`, otherwise.
//! ```
//! # use swanky_party::{*, private::*, either::*, party_map::*};
//! # party_system! {
//! #     mod ot {
//! #         Sender,
//! #         Receiver,
//! #     }
//! # }
//! # party_system! {
//! #     mod gc {
//! #         Garbler,
//! #         Evaluator,
//! #     }
//! # }
//! use std::any::TypeId;
//! assert_eq!(
//!     TypeId::of::<PartyMap<gc::Garbler, ot::Sender, ot::Receiver>>(),
//!     TypeId::of::<ot::Sender>(),
//! );
//! assert_eq!(
//!     TypeId::of::<PartyMap<gc::Evaluator, ot::Sender, ot::Receiver>>(),
//!     TypeId::of::<ot::Receiver>(),
//! );
//! ```
//!
//! We can now use [`PartyMap`] to fill-in the party!
//!
//!
//! ```
//! # use swanky_party::{*, private::*, either::*, party_map::*};
//! # // We define parties for oblivious transfer.
//! # party_system! {
//! #     mod ot {
//! #         Sender,
//! #         Receiver,
//! #     }
//! # }
//! # // And now we define parties for garbled circuits.
//! # party_system! {
//! #     mod gc {
//! #         Garbler,
//! #         Evaluator,
//! #     }
//! # }
//! # // This isn't the real OT trait; it also doesn't use network communication. It just serves as
//! # // an example.
//! # pub trait OT<P: ot::Party>: Sized {
//! #     fn init() -> Self;
//! #     fn random_ot(
//! #         self,
//! #         choices: &[PartyPrivate<ot::Receiver, P, bool>],
//! #     ) -> (
//! #         Self,
//! #         Vec<PartyEither<P, [u128; 2], u128>>,
//! #     );
//! # }
//! // For our example, we'll say that the garbler plays the role of OT sender, and the evaluator
//! // plays the role of OT receiver.
//! struct MyGarbledCircuit<P: gc::Party, OtProtocol: OT<PartyMap<P, ot::Sender, ot::Receiver>>> {
//!     ot: OtProtocol,
//!     phantom: std::marker::PhantomData<P>,
//! }
//! ```
//!
//! Now we've got everything sorted at the type-level, but we still need to be able to _use_ the
//! `PartyMap`ped values.
//!
//! For this, we have `map_evidence_party0` and `map_evidence_party1`:
//!
//! ```
//! # use swanky_party::{*, private::*, either::*, party_map::*};
//! # // We define parties for oblivious transfer.
//! # party_system! {
//! #     mod ot {
//! #         Sender,
//! #         Receiver,
//! #     }
//! # }
//! # // And now we define parties for garbled circuits.
//! # party_system! {
//! #     mod gc {
//! #         Garbler,
//! #         Evaluator,
//! #     }
//! # }
//! # // This isn't the real OT trait; it also doesn't use network communication. It just serves as
//! # // an example.
//! # pub trait OT<P: ot::Party>: Sized {
//! #     fn init() -> Self;
//! #     fn random_ot(
//! #         self,
//! #         choices: &[PartyPrivate<ot::Receiver, P, bool>],
//! #     ) -> (
//! #         Self,
//! #         Vec<PartyEither<P, [u128; 2], u128>>,
//! #     );
//! # }
//! # // For our example, we'll say that the garbler plays the role of OT sender, and the evaluator
//! # // plays the role of OT receiver.
//! # struct MyGarbledCircuit<P: gc::Party, OtProtocol: OT<PartyMap<P, ot::Sender, ot::Receiver>>> {
//! #     ot: OtProtocol,
//! #     phantom: std::marker::PhantomData<P>,
//! # }
//! impl<P: gc::Party, OtProtocol: OT<PartyMap<P, ot::Sender, ot::Receiver>>> MyGarbledCircuit<P, OtProtocol> {
//!     pub fn do_ot_things(&self) {
//!         /* ... Garbled circuit operations ... */
//!
//!         /* Need to call e.g. random_ot; only allowed for evaluator */
//!         match P::WHICH {
//!             gc::WhichParty::Garbler(e) => { /* ... Garbler things ... */ },
//!             gc::WhichParty::Evaluator(e) => {
//!                 /* Use map_evidence_party1 to convert e into evidence that PartyMap<P, ot::Sender, ot::Receiver> == ot::Receiver */
//!                 let ev_ot = map_evidence_party1::<P, ot::Sender, ot::Receiver>(e);
//!
//!                 /* ... Use ev_ot to run receiver-only code ... */
//!             }
//!         }
//!     }
//! }
//! ```

use crate::{
    GenericParty, Party0, Party1,
    either::raw::{self, bounds, is_t0, is_t1},
    ty_eq::{EqualityProposition, Witness},
};

/// If `P` is `Party0`, then output `P0`. Otherwise output `P1`.
///
/// While `P0` and `P1` must share a [`PartySystem`](crate::PartySystem), `P`'s `PartySystem`
/// doesn't need to match `P0` or `P1`'s.
///
/// ```
/// # use swanky_party::{*, private::*, either::*, party_map::*};
/// // We define parties for oblivious transfer.
/// party_system! {
///     mod ot {
///         Sender,
///         Receiver,
///     }
/// }
/// // And now we define parties for garbled circuits.
/// party_system! {
///     mod gc {
///         Garbler,
///         Evaluator,
///     }
/// }
///
/// use std::any::TypeId;
/// assert_eq!(
///     TypeId::of::<PartyMap<gc::Garbler, ot::Sender, ot::Receiver>>(),
///     TypeId::of::<ot::Sender>(),
/// );
/// assert_eq!(
///     TypeId::of::<PartyMap<gc::Evaluator, ot::Sender, ot::Receiver>>(),
///     TypeId::of::<ot::Receiver>(),
/// );
/// assert_eq!(
///     TypeId::of::<PartyMap<gc::Garbler, ot::Receiver, ot::Sender>>(),
///     TypeId::of::<ot::Receiver>(),
/// );
/// assert_eq!(
///     TypeId::of::<PartyMap<gc::Evaluator, ot::Receiver, ot::Sender>>(),
///     TypeId::of::<ot::Sender>(),
/// );
/// assert_eq!(
///     TypeId::of::<PartyMap<gc::Evaluator, ot::Sender, ot::Sender>>(),
///     TypeId::of::<ot::Sender>(),
/// );
/// ```
pub type PartyMap<P, P0, P1> = raw::RawEither<bounds::GenericParty, P, P0, P1>;

/// Convert evidence that `P == Party0<P>` into evidence that
/// `PartyMap<P, P0, P1> == P0`
///
/// Useful when reasoning about sub-protocols given knowledge about
/// which super-protocol participant is running.
#[inline(always)]
pub const fn map_evidence_party0<
    // P can have a different PartySystem than P0/P1
    P: GenericParty,
    P0: GenericParty,
    P1: GenericParty<PartySystem = P0::PartySystem>,
>(
    w: Witness<impl EqualityProposition<P, Party0<P>>>,
) -> Witness<impl EqualityProposition<PartyMap<P, P0, P1>, P0>> {
    is_t0::<bounds::GenericParty, _, _, _>(w).sym()
}

/// Convert evidence that `P == Party1<P>` into evidence that
/// `PartyMap<P, P0, P1> == P1`
///
/// Useful when reasoning about sub-protocols given knowledge about
/// which super-protocol participant is running.
#[inline(always)]
pub const fn map_evidence_party1<
    // P can have a different PartySystem than P0/P1
    P: GenericParty,
    P0: GenericParty,
    P1: GenericParty<PartySystem = P0::PartySystem>,
>(
    w: Witness<impl EqualityProposition<P, Party1<P>>>,
) -> Witness<impl EqualityProposition<PartyMap<P, P0, P1>, P1>> {
    is_t1::<bounds::GenericParty, _, _, _>(w).sym()
}
