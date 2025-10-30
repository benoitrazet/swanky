//! Support for types indexed by a _party_.
#![warn(missing_docs)]

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
/// # use swanky_party2::TheParty0;
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
/// # use swanky_party2::TheParty1;
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
    /// # use swanky_party2::{party_system, PartySystem};
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
    /// # use swanky_party2::{party_system, PartySystem};
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
#[derive(Clone, Copy)]
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
/// # use swanky_party2::*;
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
/// # use swanky_party2::*;
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
/// # use swanky_party2::*;
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
