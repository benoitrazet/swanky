//! Support for types indexed by a _party_.
//!
//! This crate enables code de-duplication in the context of
//! multi-party protocols, both generically and with respect to a
//! specific _party system_ (that is, the pair of participants in a
//! two-party protocol).
//!
//! Using the [`party_system`] macro, a [`PartySystem`] can be defined
//! that uses names appropriate to the protocol context.
//! The following defines the classic `Alice` and `Bob` `PartySystem`:
//!
//! ```
//! use swanky_party::{party_system};
//! party_system! {
//!     mod ps {
//!         Alice,
//!         Bob,
//!     }
//! }
//! ```
//!
//! With this short invocation, a significant amount of expressive
//! power is achieved:
//!
//! - `ps::Party` can be used to implement functions and types that
//!   are generic over the system's participants.
//! - Given `P: ps::Party`, `P::WHICH` is a constant `ps::WhichParty`,
//!   which is `ps::WhichParty::Alice(e)` when `P` is `Alice` (`e`
//!   being _evidence_ of the type equality used to run code specific
//!   to Alice).
//!   Naturally, `ps::WhichParty::Bob(e)` gives evidence that `P` is
//!   `Bob`.
//!   These are all compatible with `GenericParty` and
//!   `GenericWhichParty` by design.
//!
//! All party systems can be used with the following generic modules
//! to accomplish a variety of tasks, from specifying party-private
//! data to associating one party system with another:
//!
//! - [`either`] defines `PartyEither` and `PartyEitherCopy`.
//!   In short, these types are `repr(transparent)` to one type or
//!   another, dependent on context (i.e. which participant is running
//!   protocol code), meaning they cost nothing after specialization.
//!   For complex cases, [`either::raw`] (the backing of
//!   `PartyEither`) is available for use.
//! - [`party_map`] allows party systems to be 'mapped' to one
//!   another; this is useful when implementing sub-protocols, where
//!   participants in the super-protocol must be correctly
//!   associated with participants in the sub-protocol.
//! - [`private`] exposes types that provide zero-cost representations
//!   of data that is private to a protocol participant.
//! - [`ty_eq`] implements reasoning over type equality, value-level
//!   evidence of which is used to write code that (for instance) can
//!   only be run by a specific participant in a `PartySystem`.
//!   Most importantly, it provides the [`Witness`] type, which is a
//!   value-level piece of evidence that some [`EqualityProposition`]
//!   is true.
//!   This is used to safely invoke functions that are
//!   participant-specific, for instance.
//!
//! Here is a very contrived example using most of these ideas and
//! building on the code above:
//!
//! ```
//! # use swanky_party::{party_system, either::*, ty_eq::*};
//! # party_system! {
//! #     mod ps {
//! #         Alice,
//! #         Bob,
//! #     }
//! # }
//! # use ps::*;
//! struct AliceOnlyData;
//! struct BobOnlyData;
//!
//! struct Info<P: Party> {
//!     // ... other fields common to both parties ...
//!
//!     // A field that is `AliceOnlyData` when `P == Alice` and
//!     // `BobOnlyData` when `P == Bob`
//!     participant_specific_data: PartyEither<P, AliceOnlyData, BobOnlyData>,
//! }
//!
//! fn do_something<P: Party>(info: Info<P>) {
//!     /* ... Operations common to both participants ... */
//!     match P::WHICH {
//!         // e is a `Witness` to the fact that `P` is the
//!         // participant in question; participant-specific
//!         // operations can use this evidence to guarantee the right
//!         // participant is working
//!         WhichParty::Alice(e) => { /* ... Alice-specific operations ... */ }
//!         WhichParty::Bob(e) => { /* ... Bob-specific operations ...  */ }
//!     }
//! }
//!
//! fn do_something_alice<P: Party>(info: Info<P>, ev: Witness<impl EqualityProposition<P, Alice>>) {
//!     /* ... Things only Alice can do ... */
//! }
//! ```
//!
//! Sometimes, however, a protocol isn't related to a particular party
//! system (see, for example,
//! [`swanky_f_eq`](../swanky_f_eq/index.html)); in cases like this,
//! the protocol can be defined over `P: GenericParty` so that it can
//! be used with _any_ concrete `PartySystem`.
//!
//! The [`swanky_channel`](../swanky_channel/index.html)
//! `communicate(...)` method is an example of this in practice:
//!
//! ```ignore
//! pub fn communicate<
//!     PrivateTo: GenericParty<PartySystem = P::PartySystem>,
//!     P: GenericParty,
//!     T: CanonicalSerialize,
//! >(
//!     &mut self,
//!     p: swanky_party::private::PartyPrivateCopy<PrivateTo, P, T>,
//! ) -> swanky_error::Result<T>
//! ```
#![deny(missing_docs)]

#[macro_use]
mod macros;

pub mod either;
pub mod party_map;
pub mod private;
pub mod ty_eq;

#[doc(hidden)]
pub use macros::__macro_internal;

use crate::ty_eq::{EqualityProposition, Witness};

/// A trait alias for [`GenericParty`]s which are `Party0` of its [`PartySystem`].
///
/// You can't implement this trait yourself, but you can use it at the type-level. If you're
/// writing a _function_ which requires a party to be `Party0`, you'd typically do so via an
/// argument of type `Witness<impl EqualityProposition<P, Party0<P>>>`, _not_ using [`TheParty0`].
///
/// # Example
/// ```
/// # use swanky_party::TheParty0;
/// pub trait Foo {
///     type Output<P: TheParty0>;
/// }
/// ```
pub trait TheParty0:
    GenericParty<RawImpl = either::raw::internal::Party0Impl, PartySystem: PartySystem<Party0 = Self>>
{
}
impl<
    P: GenericParty<
            RawImpl = either::raw::internal::Party0Impl,
            PartySystem: PartySystem<Party0 = Self>,
        >,
> TheParty0 for P
{
}

/// A trait alias for [`GenericParty`]s which are `Party1` of its [`PartySystem`].
///
/// You can't implement this trait yourself, but you can use it at the type-level. If you're
/// writing a _function_ which requires a party to be `Party1`, you'd typically do so via an
/// argument of type `Witness<impl EqualityProposition<P, Party1<P>>>`, _not_ using [`TheParty1`].
///
/// # Example
/// ```
/// # use swanky_party::TheParty1;
/// pub trait Foo {
///     type Output<P: TheParty1>;
/// }
/// ```
pub trait TheParty1:
    GenericParty<RawImpl = either::raw::internal::Party1Impl, PartySystem: PartySystem<Party1 = Self>>
{
}
impl<
    P: GenericParty<
            RawImpl = either::raw::internal::Party1Impl,
            PartySystem: PartySystem<Party1 = Self>,
        >,
> TheParty1 for P
{
}

/// A pair of parties that will operate opposite each other.
///
/// [`PartySystem`]s are created via [`party_system`]
pub trait PartySystem:
    'static + Sized + Copy + Eq + Send + Sync + Ord + std::fmt::Debug + std::hash::Hash + Default
{
    /// A `PartySystem`-specific version of [`GenericWhichParty`] where variants are labelled with
    /// the names of the parties in the system.
    type WhichParty<P: GenericParty<PartySystem = Self>>: 'static
        + Send
        + Sync
        + Copy
        + Eq
        + Ord
        + std::hash::Hash
        + std::fmt::Debug
        + Sized
        + From<GenericWhichParty<P>>
        + Into<GenericWhichParty<P>>;
    /// What is the type of the 0-th party in the pair?
    ///
    /// ```
    /// # use swanky_party::{party_system, PartySystem};
    /// use std::any::TypeId;
    /// party_system! {
    ///     mod ps {
    ///         Alice,
    ///         Bob,
    ///     }
    /// }
    /// assert_eq!(TypeId::of::<ps::Alice>(), TypeId::of::<<ps::PartySystem as PartySystem>::Party0>());
    /// ```
    type Party0: GenericParty<PartySystem = Self> + TheParty0;
    /// What is the type of the 1-st party in the pair?
    ///
    /// ```
    /// # use swanky_party::{party_system, PartySystem};
    /// use std::any::TypeId;
    /// party_system! {
    ///     mod ps {
    ///         Alice,
    ///         Bob,
    ///     }
    /// }
    /// assert_eq!(TypeId::of::<ps::Bob>(), TypeId::of::<<ps::PartySystem as PartySystem>::Party1>());
    /// ```
    type Party1: GenericParty<PartySystem = Self> + TheParty1;
}

/// Which party is `P`? `Party0` or `Party1`
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GenericWhichParty<P: GenericParty> {
    /// Evidence that `P` is `Party0`
    Party0(Witness<P::IsParty0>),
    /// Evidence that `P` is `Party1`
    Party1(Witness<P::IsParty1>),
}

/// A Party in a multi-party computation.
pub trait GenericParty:
    'static + Send + Sync + Copy + Eq + Ord + std::hash::Hash + std::fmt::Debug + Sized + Default
{
    /// An [`EqualityProposition`] that says that `Self == Party0`
    type IsParty0: EqualityProposition<Self, <Self::PartySystem as PartySystem>::Party0>
        + EqualityProposition<<Self::PartySystem as PartySystem>::Party0, Self>;
    /// An [`EqualityProposition`] that says that `Self == Party1`
    type IsParty1: EqualityProposition<Self, <Self::PartySystem as PartySystem>::Party1>
        + EqualityProposition<<Self::PartySystem as PartySystem>::Party1, Self>;
    /// The `PartySystem` that this Party is a member of
    type PartySystem: PartySystem;
    /// Evidence of which party (`Party0` or `Party1`) `Self` is
    const GENERIC_WHICH: GenericWhichParty<Self>;
    #[doc(hidden)]
    /// The underlying [`RawEither`](raw::RawEither) implementation
    type RawImpl: either::raw::internal::Impl<Self>;
}

/// The opposite/peer party of `P`
/// # Example
/// ```
/// # use swanky_party::*;
/// use std::any::TypeId;
/// party_system! {
///     mod ps {
///         Alice,
///         Bob,
///     }
/// }
/// use ps::*;
/// assert_eq!(TypeId::of::<Bob>(), TypeId::of::<OppositeParty<Alice>>());
/// assert_eq!(TypeId::of::<Alice>(), TypeId::of::<OppositeParty<Bob>>());
/// ```
pub type OppositeParty<P> = party_map::PartyMap<
    P,
    <<P as GenericParty>::PartySystem as PartySystem>::Party1,
    <<P as GenericParty>::PartySystem as PartySystem>::Party0,
>;

/// Party0 of `P`'s [`PartySystem`]
///
/// # Example
/// ```
/// # use swanky_party::*;
/// use std::any::TypeId;
/// party_system! {
///     mod ps {
///         Alice,
///         Bob,
///     }
/// }
/// use ps::*;
/// assert_eq!(TypeId::of::<Alice>(), TypeId::of::<Party0<Alice>>());
/// assert_eq!(TypeId::of::<Alice>(), TypeId::of::<Party0<Bob>>());
/// ```
pub type Party0<P> = <<P as GenericParty>::PartySystem as PartySystem>::Party0;

/// Party1 of `P`'s [`PartySystem`]
///
/// # Example
/// ```
/// # use swanky_party::*;
/// use std::any::TypeId;
/// party_system! {
///     mod ps {
///         Alice,
///         Bob,
///     }
/// }
/// use ps::*;
/// assert_eq!(TypeId::of::<Bob>(), TypeId::of::<Party1<Alice>>());
/// assert_eq!(TypeId::of::<Bob>(), TypeId::of::<Party1<Bob>>());
/// ```
pub type Party1<P> = <<P as GenericParty>::PartySystem as PartySystem>::Party1;
