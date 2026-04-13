//! Advanced version of [`PartyEither`](crate::either::PartyEither) (not needed for most use-cases)
//!
//! This module defines [`RawEither`], the type that powers both
//! [`PartyEither`](crate::either::PartyEither) and [`PartyPrivate`](crate::private::PartyPrivate).
//!
//!
//! `PartyEither<P0, A, B>` is a `repr(transparent)` container holding type `A`, but
//! `PartyEither<P0, A, B>` is not _the same type as_ `A`.
//! ```
//! # use swanky_party::{party_system, either::PartyEither};
//! # use std::any::TypeId;
//! party_system! {
//!     mod ps {
//!         P0,
//!         P1,
//!     }
//! }
//! use ps::*;
//! assert_eq!(
//!     std::mem::size_of::<PartyEither<P0, u8, u128>>(),
//!     std::mem::size_of::<u8>()
//! );
//! assert_ne!(
//!     TypeId::of::<PartyEither<P0, u8, u128>>(),
//!     TypeId::of::<u8>(),
//! );
//! ```
//!
//! Unlike [`PartyEither`](crate::either::PartyEither), [`RawEither`] is _equal_ to its output
//! type.
//! ```
//! # use swanky_party::{party_system, either::raw::{bounds, RawEither}};
//! # use std::any::TypeId;
//! # party_system! {
//! #     mod ps {
//! #         P0,
//! #         P1,
//! #     }
//! # }
//! # use ps::*;
//! assert_eq!(
//!     std::mem::size_of::<RawEither<bounds::Any, P0, u8, u128>>(),
//!     std::mem::size_of::<u8>()
//! );
//! assert_eq!(
//!     TypeId::of::<RawEither<bounds::Any, P0, u8, u128>>(),
//!     TypeId::of::<u8>(),
//! );
//! ```
//!
//! This type equality makes [`RawEither`] harder to use than
//! [`PartyEither`](crate::either::PartyEither), but also gives it extra powers that are useful in
//! some cases.

use crate::ty_eq::{
    EqualityProposition as EqProp, Generic, GenericOut, IsSameType, TrueEqualityProposition,
    Witness, generics,
};
use crate::{GenericParty, Party0, Party1, PartySystem, TheParty0, TheParty1};
use std::hash::Hash;
use std::marker::PhantomData;

/// A type that is equal to `T0` when `P == Party0<P>` and is equal to `T1` otherwise.
///
/// # Construction and Extraction
///
/// [`PartyEither`](crate::either::PartyEither) has [`new()`](crate::either::PartyEither::new)
/// and [`into_inner()`](crate::either::PartyEither::into_inner) to construct and extract,
/// respectively, its contents. `RawEither` doesn't have methods for that. Instead, if `P` is
/// _literally_ `Party0`, then Rust will conclude that `RawEither<Party0, T0, T1> == T0` (and
/// respectively for `Party1`).
///
/// ```
/// # use swanky_party::{party_system, either::raw::{RawEither, bounds}};
/// party_system! {
///     mod ps {
///         P0,
///         P1,
///     }
/// }
/// use ps::*;
/// fn construct_p0(x: i32) -> RawEither<bounds::Any, P0, i32, String> {
///     x
/// }
/// fn construct_p1(x: String) -> RawEither<bounds::Any, P1, i32, String> {
///     x
/// }
///
/// fn extract_p0(x: RawEither<bounds::Any, P0, i32, String>) -> i32 {
///     x
/// }
/// fn extract_p1(x: RawEither<bounds::Any, P1, i32, String>) -> String {
///     x
/// }
/// ```
///
/// However, this only works if Rust _knows_ which party is in-use.
/// ```compile_fail
/// # use swanky_party::{
/// #     party_system,
/// #     either::raw::{RawEither, bounds},
/// #     ty_eq::{Witness, EqualityProposition},
/// # };
/// # party_system! {
/// #     mod ps {
/// #         P0,
/// #         P1,
/// #     }
/// # }
/// # use ps::*;
/// use swanky_party::Party0;
/// fn construct_p0<P: Party>(
///     x: i32,
///     ev: Witness<impl EqualityProposition<P, Party0<P>>>,
/// ) -> RawEither<bounds::Any, P, i32, String> {
///     // Rust doesn't know whether P == P0 or not! We do, though. We have the equality!
///     x
/// }
/// ```
///
/// To fix this, we can use [`is_t0`] and [`is_t1`] to _cast_ a `RawEither` and change which party
/// its associated with. Thus, we can turn a `RawEither<bounds::Any, P0, i32, String>` (i.e. `i32`)
/// into a `RawEither<bounds::Any, P, i32, String>`.
/// ```
/// # use swanky_party::{
/// #     party_system,
/// #     either::raw::{RawEither, bounds},
/// #     ty_eq::{Witness, EqualityProposition},
/// # };
/// # party_system! {
/// #     mod ps {
/// #         P0,
/// #         P1,
/// #     }
/// # }
/// # use ps::*;
/// # use swanky_party::Party0;
/// use swanky_party::either::raw::{is_t0, is_t1};
/// fn construct_p0<P: Party>(
///     x: i32,
///     ev: Witness<impl EqualityProposition<P, Party0<P>>>,
/// ) -> RawEither<bounds::Any, P, i32, String> {
///     is_t0::<bounds::Any, _, _, _>(ev).cast(x)
/// }
///
/// fn extract<P: Party>(x: RawEither<bounds::Any, P, i32, String>) -> String {
///     match P::WHICH {
///         WhichParty::P0(ev) => format!(
///             "Hex Number! 0x{:X}",
///             is_t0::<bounds::Any, P, _, _>(ev).sym().cast(x),
///         ),
///         WhichParty::P1(ev) => format!(
///             "Lower-case string! {}",
///             is_t1::<bounds::Any, P, _, _>(ev).sym().cast(x).to_lowercase(),
///         ),
///     }
/// }
///
/// // While we need to use conversions _inside_ extract, when invoking extract, if we use a
/// // concrete party as the type argument, Rust won't require us to perform any conversions.
/// assert_eq!(
///     extract::<P0>(15).as_str(),
///     "Hex Number! 0xF",
/// );
/// assert_eq!(
///     extract::<P1>("SqUiDwArD".to_string()).as_str(),
///     "Lower-case string! squidward",
/// );
/// ```
///
/// # Bound
///
/// See [`EitherBound`] for more information on `Bound`.
///
#[allow(type_alias_bounds)] // Makes the docs better
pub type RawEither<Bound: EitherBound<T0, T1>, P: GenericParty, T0, T1> =
    <Bound as EitherBound<T0, T1>>::RawEither<P>;

/// Return an [`EqualityProposition`](EqProp) [`Witness`] between (roughly)
/// `G<RawEither<P, T0, T1>>` and `RawEither<P, G<T0>, G<T1>>`.
///
/// # Example
/// ```
/// # use swanky_party::{
/// #     party_system, GenericParty,
/// #     either::raw::{RawEither, bounds, either_type_substitution},
/// #     ty_eq::{Witness, EqualityProposition, generics, Generic},
/// # };
/// fn raw_either_as_ref<'a, P: GenericParty, T0, T1>(
///     either: &'a RawEither<bounds::Any, P, T0, T1>
/// ) -> RawEither<bounds::Any, P, &'a T0, &'a T1> {
///     const {
///         either_type_substitution::<generics::Ref, bounds::Any, bounds::Any, P, T0, T1>()
///     }.cast(either)
/// }
///
/// // You can't do this with PartyEither
/// use std::collections::HashSet;
/// use std::hash::Hash;
/// fn pull_hash_set<P: GenericParty, T0: Hash + Eq, T1: Hash + Eq>(
///     hs: RawEither<bounds::Any, P, HashSet<T0>, HashSet<T1>>
/// ) -> HashSet<RawEither<bounds::EqHash, P, T0, T1>> {
///     struct HashSetGeneric;
///     impl<T: Eq + Hash> Generic<T> for HashSetGeneric {
///         type Output = HashSet<T>;
///     }
///     const {
///         either_type_substitution::<HashSetGeneric, bounds::EqHash, bounds::Any, P, _, _>()
///             .sym()
///     }.cast(hs)
/// }
/// ```
#[inline(always)]
pub const fn either_type_substitution<
    G: Generic<RawEither<BIn, P, T0, T1>>
        + Generic<T0>
        + Generic<T1>
        + Generic<RawEither<BIn, Party0<P>, T0, T1>>
        + Generic<RawEither<BIn, Party1<P>, T0, T1>>,
    BIn: EitherBound<T0, T1>,
    BOut: EitherBound<GenericOut<G, T0>, GenericOut<G, T1>>,
    P: GenericParty,
    T0,
    T1,
>() -> Witness<
    impl EqProp<
        GenericOut<G, RawEither<BIn, P, T0, T1>>,
        RawEither<BOut, P, GenericOut<G, T0>, GenericOut<G, T1>>,
    >,
> {
    match P::GENERIC_WHICH {
        crate::GenericWhichParty::Party0(ev) => is_t0::<BIn, P, T0, T1>(ev)
            .sym()
            .with_generic::<G, _, _>()
            .and_then(is_t0::<BOut, P, GenericOut<G, T0>, GenericOut<G, T1>>(ev))
            .join_left()
            .join(),
        crate::GenericWhichParty::Party1(ev) => is_t1::<BIn, P, T0, T1>(ev)
            .sym()
            .with_generic::<G, _, _>()
            .and_then(is_t1::<BOut, P, GenericOut<G, T0>, GenericOut<G, T1>>(ev))
            .join_right()
            .join(),
    }
}

/// Given that `P` is party 0, conclude that `RawEither<T0, T1> == T0`
///
/// ```
/// # use swanky_party::{
/// #     party_system, Party0,
/// #     either::raw::{RawEither, bounds, is_t0},
/// #     ty_eq::{Witness, EqualityProposition},
/// # };
/// party_system! {
///     mod ps {
///         P0,
///         P1,
///     }
/// }
/// use ps::*;
/// fn construct_p0<P: Party>(
///     x: i32,
///     ev: Witness<impl EqualityProposition<P, Party0<P>>>,
/// ) -> RawEither<bounds::Any, P, i32, String> {
///     is_t0::<bounds::Any, _, _, _>(ev).cast(x)
/// }
/// ```
#[inline(always)]
pub const fn is_t0<B: EitherBound<T0, T1>, P: GenericParty, T0, T1>(
    ev: Witness<impl EqProp<P, Party0<P>>>,
) -> Witness<impl EqProp<T0, RawEither<B, P, T0, T1>>> {
    <B::Witness0<Party0<P>> as EqProp<_, _>>::SUMMON
        .unwrap()
        .and_then(
            ev.sym()
                .with_generic::<generics::RawEitherParty<B, T0, T1>, _, _>(),
        )
}

/// Given that `P` is party 1, conclude that `RawEither<T0, T1> == T1`
///
/// ```
/// # use swanky_party::{
/// #     party_system, Party1,
/// #     either::raw::{RawEither, bounds, is_t1},
/// #     ty_eq::{Witness, EqualityProposition},
/// # };
/// party_system! {
///     mod ps {
///         P0,
///         P1,
///     }
/// }
/// use ps::*;
/// fn construct_p1<P: Party>(
///     x: String,
///     ev: Witness<impl EqualityProposition<P, Party1<P>>>,
/// ) -> RawEither<bounds::Any, P, i32, String> {
///     is_t1::<bounds::Any, _, _, _>(ev).cast(x)
/// }
/// ```
#[inline(always)]
pub const fn is_t1<B: EitherBound<T0, T1>, P: GenericParty, T0, T1>(
    ev: Witness<impl EqProp<P, Party1<P>>>,
) -> Witness<impl EqProp<T1, RawEither<B, P, T0, T1>>> {
    <B::Witness1<Party1<P>> as EqProp<_, _>>::SUMMON
        .unwrap()
        .and_then(
            ev.sym()
                .with_generic::<generics::RawEitherParty<B, T0, T1>, _, _>(),
        )
}

/// A trait indicating that `T0, T1` meet a given type bound.
///
/// Bounds can only be specified in this crate. The [`EitherBound`] instances are found in the
/// [`bounds`] module.
///
/// Much like we have [`PartyEither`](crate::either::PartyEither) and
/// [`PartyEitherCopy`](crate::either::PartyEitherCopy), `RawEither` achieves the same effect via
/// its `Bound` type parameter. The `Bound` parameter will tell Rust what requirements must be
/// imposed on `T0` and `T1` and, consequently, on any resulting `RawEither`.
///
/// `RawEither<bounds::Any, P, T0, T1>` is the equivalent of `PartyEither`, and
/// `RawEither<bounds::Copy, P, T0, T1>` is the equivalent of `PartyEitherCopy`.
///
/// Unfortunately, Rust cannot infer these `Bound`s, so we need to manually specify them.
///
/// ## Example
/// ```compile_fail
/// # use swanky_party::{party_system, either::raw::{bounds, RawEither}};
/// # use std::any::TypeId;
/// party_system! {
///     mod ps {
///         P0,
///         P1,
///     }
/// }
/// use ps::*;
/// // Even though T0 and T1 are both Copy, Rust doesn't know that this means that the resulting
/// // RawEither is _also_ Copy.
/// fn ex1<P: Party, T0: Copy, T1: Copy>(either: RawEither<bounds::Any, P, T0, T1>) -> impl Copy {
///     either
/// }
/// ```
/// ```
/// # use swanky_party::{party_system, either::raw::{bounds, RawEither}};
/// # party_system! {
/// #     mod ps {
/// #         P0,
/// #         P1,
/// #     }
/// # }
/// # use ps::*;
/// // Using bounds::Copy fixes the issue.
/// fn ex2<P: Party, T0: Copy, T1: Copy>(either: RawEither<bounds::Copy, P, T0, T1>) -> impl Copy {
///     either
/// }
/// ```
///
/// Even though Rust won't automatically figure out that `ex1`'s argument is `Copy` we can manually
/// convert `RawEither`s between bounds (so long as `T0` and `T1` meet the bound).
/// ```
/// # use swanky_party::{party_system, either::raw::{bounds, RawEither}};
/// # party_system! {
/// #     mod ps {
/// #         P0,
/// #         P1,
/// #     }
/// # }
/// # use ps::*;
/// fn ex1_fixed<P: Party, T0: Copy, T1: Copy>(
///     either: RawEither<bounds::Any, P, T0, T1>
/// ) -> impl Copy {
///     RawEither::<bounds::Copy, P, T0, T1>::from(either)
/// }
/// ```
///
/// We can also use [`ty_eq`](crate::ty_eq) to perform more complicated conversions.
/// ```
/// # use swanky_party::{party_system, either::raw::{bounds, RawEither}};
/// # party_system! {
/// #     mod ps {
/// #         P0,
/// #         P1,
/// #     }
/// # }
/// # use ps::*;
/// use swanky_party::ty_eq::{generics, IsSameType};
/// fn ex1_references<'a, P: Party, T0: Copy, T1: Copy>(
///     either: &'a RawEither<bounds::Any, P, T0, T1>,
/// ) -> &'a RawEither<bounds::Copy, P, T0, T1>{
///     let ev = <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
///         RawEither<bounds::Any, P, T0, T1>,
///     >>::WITNESS;
///     ev.sym().with_generic::<generics::Ref, _, _>().cast(either)
/// }
/// ```
pub trait EitherBound<T0, T1> {
    /// The underlying implementation of [`RawEither`]
    ///
    /// [`RawEither`] is a type-alias for this associated type. (We prefer using the [`RawEither`]
    /// type alias because it's shorter.)
    type RawEither<P: GenericParty>: IsSameType<RawEither<bounds::Any, P, T0, T1>>;
    /// An `EqualityProposition` that shows that `RawEither<Self, Party0, T0, T1> == T0`
    ///
    /// This is used internally in [`is_t0`]
    #[doc(hidden)]
    type Witness0<P: TheParty0>: EqProp<T0, RawEither<Self, P, T0, T1>>;
    /// An `EqualityProposition` that shows that `RawEither<Self, Party1, T0, T1> == T1`
    ///
    /// This is used internally in [`is_t1`]
    #[doc(hidden)]
    type Witness1<P: TheParty1>: EqProp<T1, RawEither<Self, P, T0, T1>>;
}

macro_rules! define_bounds {
    ($(
        $(#[$meta:meta])*
        type $bound_name:ident<
            T0,
            T1
            $(,$tvar:ident)*
            $(,)?
        > $(where [$($bound:tt)*] [TOut: $($out_bound:tt)*])?;
    )*) => {
        pub(crate) mod internal {
            use super::*;
            pub trait Impl<P: GenericParty> {
                $(type $bound_name<$($tvar,)* T0, T1>
                    : IsSameType<Self::Any<T0, T1>> $(+ $($out_bound)* where $($bound)*)?;)*
            }
            /// The internal Either implementation for `Party0`s
            pub enum Party0Impl {}
            impl<P: GenericParty<PartySystem: PartySystem<Party0 = P>>>
                Impl<P> for Party0Impl
            {
                $(type $bound_name<$($tvar,)* T0, T1>
                    = T0 $(where $($bound)*)?;)*
            }
            /// The internal Either implementation for `Party1`s
            pub enum Party1Impl {}
            impl<P: GenericParty<PartySystem: PartySystem<Party1 = P>>>
                Impl<P> for Party1Impl
            {
                $(type $bound_name<$($tvar,)* T0, T1>
                    = T1 $(where $($bound)*)?;)*
            }
        }
        use internal::*;
        pub mod bounds {
            //! Trait bounds that can be imposed on [`RawEither`]s.
            //!
            //! See [`EitherBound`] for more information.
            use super::*;
            $(
                $(#[$meta])*
                #[derive(
                    Clone,
                    Copy,
                    PartialEq,
                    Eq,
                    PartialOrd,
                    Ord,
                    Debug,
                    Hash,
                    Default,
                )]
                pub struct $bound_name<$($tvar),*> {
                    phantom: PhantomData<($($tvar),*)>,
                }
                impl<$($tvar,)*T0, T1>
                    EitherBound<T0, T1> for $bound_name<$($tvar),*>
                $(where $($bound)*)?
                {
                    type RawEither<P: crate::GenericParty> =
                        <P::RawImpl as Impl<P>>::$bound_name<$($tvar,)*T0, T1>;
                    type Witness0<P: TheParty0> = TrueEqualityProposition;
                    type Witness1<P: TheParty1> = TrueEqualityProposition;
                }
            )*
        }
    };
}

define_bounds! {
    /// No restriction on the types in the [`RawEither`]
    type Any<T0, T1>;
    /// Types in the [`RawEither`] must be [`Copy`](std::marker::Copy)
    type Copy<T0, T1>
        where [T0: std::marker::Copy, T1: std::marker::Copy] [TOut: std::marker::Copy];
    /// Types in the [`RawEither`] must be [`Eq`] and [`Hash`]
    type EqHash<T0, T1>
        where [T0: Eq + Hash, T1: Eq + Hash] [TOut: Eq + Hash];
    /// Types in the [`RawEither`] must be [`GenericParty`](crate::GenericParty)s of the same [`PartySystem`]
    type GenericParty<T0, T1>
        where
            [T0: crate::GenericParty, T1: crate::GenericParty<PartySystem = T0::PartySystem>]
            [TOut: crate::GenericParty<PartySystem = T0::PartySystem>];
    /// Types in the [`RawEither`] must be
    /// [`EqualityProposition`](crate::ty_eq::EqualityProposition)s asserting that `A == B`
    type EqualityProposition<T0, T1, A, B>
        where
            [T0: super::EqProp<A, B>, T1: super::EqProp<A, B>]
            [TOut: super::EqProp<A, B>];
}

#[cfg(test)]
mod tests {
    use super::*;

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    fn raw_either_as_ref<P: GenericParty, T0, T1>(
        either: &RawEither<bounds::Any, P, T0, T1>,
    ) -> RawEither<bounds::Any, P, &T0, &T1> {
        either_type_substitution::<generics::Ref, bounds::Any, bounds::Any, P, T0, T1>()
            .cast(either)
    }

    #[test]
    fn ref_either_type_substitution_cast() {
        let re_a: RawEither<bounds::Any, PartyA, i32, String> = 17;
        let re_a_ref = raw_either_as_ref::<PartyA, _, String>(&re_a);
        assert_eq!(&re_a, re_a_ref);

        let re_b: RawEither<bounds::Any, PartyB, i32, String> = "test".to_string();
        let re_b_ref = raw_either_as_ref::<PartyB, i32, _>(&re_b);
        assert_eq!(&re_b, re_b_ref);
    }
}
