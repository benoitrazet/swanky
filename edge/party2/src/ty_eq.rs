#![deny(unsafe_code)]
//! Utilities for describing equalities between types.
//!
//! An important requirement of the `party2` core API is _low-cost
//! abstraction_; that is, making your code generic over a
//! [`crate::PartySystem`] should not incur any surprise memory or
//! runtime costs.
//!
//! The realities of making this happen are, given certain
//! 'limitations' of the Rust type system, somewhat complicated in
//! general -- ideally, we need to convince the type system that
//! the compiler-generated concretions of party-generic code have
//! types that are _actually equal_ to the 'thing' on the inside for
//! the given party.
//! This 'convincing' cannot be completely hidden; we need to, in
//! part, reflect type-level facts at the value level such that Rust
//! _can_ infer what we want and generate the most efficient code
//! possible.
//! The particular facts that must be reflected in this way to
//! accomplish the stated performance goals within Rust's limitations
//! are _type equalities_.
//!
//! This module defines this reflection, ultimately providing a
//! library capable of reasoning about equalities between complex
//! generic types (with a respectable starting point of commonly-used
//! standard library data structures like `Option` and `HashMap`).
//!
//! ## Type equality propositions
//!
//! As alluded to above, we occasionally need to reason about type
//! equality at the value level and type level simultaneously so that
//! our abstractions incur no unnecessary runtime or memory costs.
//!
//! To accomplish this in Rust, we use a trait, as this allows us to
//! simultaneously express type-level constraints _and_ provide
//! value-level manipulation via methods and associated items.
//! We restrict any misuse of the trait in downstream code (i.e.
//! implementing it in ways that are unsound with respect to Rust's
//! type system) by 'sealing' the trait.
//!
//! The trait `EqualityProposition<T0, T1>` represents the logical
//! statement `T0 == T1`, which may be true or false.
//!
//! More complex equality propositions can be derived from this basic
//! starting point:
//!
//! - `T1 == T0` (equality is symmetric)
//! - If (in addition to `T0 == T1`) `T1 == T2`, then `T0 == T2`
//!   (equality is transitive)
//! - `G<T0> == G<T1>` (type constructors are well-defined)
//! - Disjunctions with other `EqualityProposition`s of the same type
//!
//! These implied propositions are provided as associated types of the
//! `EqualityProposition` trait, as they are all themselves
//! `EqualityProposition`s (or "type-level functions" that return
//! `EqualityProposition`s).
//!
//! Generics and disjunctions are somewhat more involved due to
//! limitations of the type system, so their introduction is left to
//! the documentation of those respective types (see [`Generic`] and
//! [`JoinedTypeEqualityWitness`]).
//!
//! But how do we know if an `EqualityProposition` is true or not?
//! And, knowing this, what can we _do_ with an `EqualityProposition`
//! that is useful?
//!
//! For the first question, `EqualityProposition` provides an
//! associated `const SUMMON: Option<Witness<Self>>` that is `Some(w)`
//! if and only if the `EqualityProposition` is actually true.
//! We will say more about `Witness<P>` shortly; for now, it suffices
//! to say that having a value of this type is how we _know_ that `P`
//! is a true equality proposition.
//!
//! For the second, the answer is simple: Casting!
//! A true type equality means that the types are truly and safely
//! interchangeable -- and, importantly, have the same representation
//! in memory.
//!
//! ## The concrete `EqualityProposition`s
//!
//! Before introducing `Witness`, recall that `EqualityProposition` is
//! a _sealed_ trait, meaning we provide the only types implementing
//! it.
//! There are, in fact, only two such types:
//!
//! - `TrueEqualityProposition`: Exactly what it says; this explicitly
//!   implements `EqualityProposition<T, T>`, which is the simplest
//!   type equality imaginable (at is known true by the reflexive
//!   property, and -- arguably more importantly -- the Rust compiler
//!   itself).
//! - `NotNecessarilyTrueEqualityProposition`: This is **in practice**
//!   always a _false_ equality proposition; it is given an obnoxious
//!   name because _we can't stop you from using this where the
//!   expected `EqualityProposition` is in fact true_.
//!   As everything defined here doesn't depend on having a concrete
//!   notion of a known-false equality proposition, this doesn't
//!   affect anything.
//!
//! A `TrueEqualityProposition`, as expected, is _always_ able to
//! `SUMMON` a witness; under the hood, it's just a unit-like
//! structure type.
//!
//! On the other hand, `NotNecessarilyTrueEqualityProposition` can
//! _never_ produce a witness, as it is an enumeration type with no
//! constructors.
//!
//! Each of these types implements `EqualityProposition`, but
//! naturally only `TrueEqualityProposition` can be `Witness`ed.
//!
//! ## `Witness`ing truth / not-necessarily-truth of `EqualityProposition`s
//!
//! So, finally, what is a `Witness<P>`?
//!
//! Simply put, for a generic `P: EqualityProposition<T0, T1>`, it is
//! a value-level 'lowering' of the `EqualityProposition` itself,
//! whose existence implies that the proposition holds.
//! This implication holds under the Curry-Howard isomorphism: Types
//! are propositions, and values of types are witnesses to those
//! corresponding propositions' truth.
//!
//! Where `EqualityProposition` provided associated types (that acted
//! essentially as type-level functions to transform the proposition),
//! `Witness` provides a set of _methods_ acting on the corresponding
//! witness to a proposition, allowing it to be turned into a witness
//! for the symmetric equality proposition, a witness to a transitive
//! equality (given a witness to the intermediate equality), and so
//! on.
//!
//! Everything is tied together through the key property of
//! `EqualityProposition`: That `SUMMON` is `Some(w)` (where `w:
//! Witness<Self>`) if and only if the `EqualityProposition` is true.
//!
//! See the documentation of the types mentioned here for additional
//! detail regarding the practical use of these concepts; of
//! particular importance is [`Generic`], which is what us allows to
//! take our basic reasoning (which applies perfectly well to
//! primitive types out of the box) and allow its use over generic
//! types, exploiting the fact that type constructors are implicitly
//! well-defined.
use std::marker::PhantomData;

mod sealed {
    /// A [sealed trait](https://predr.ag/blog/definitive-guide-to-sealed-traits-in-rust/).
    ///
    /// This means that only items in the party crate can `impl` this trait.
    pub trait Sealed {}
}

/// `Generic` lets you name a generic type with a placeholder.
/// This is useful in conjunction with [`Witness`] and
/// [`EqualityProposition`] to reason about generic types.
///
/// Suppose we know that `T0 == T1`. All of the following should then be true:
/// - `&T0 == &T1`
/// - `&mut [T0] == &mut [T1]`
/// - `&mut HashSet<T0> == &mut HashSet<T1>`
/// - `&mut HashMap<String, T0> == &mut HashMap<String, T1>`
/// - and many more!
///
/// Rather than trying to enumerate (in this crate) all of the possible ways you could write a
/// `Generic` type, we let you define your own generic helpers!
///
/// ```
/// # use swanky_party2::ty_eq::*;
/// # use std::collections::{HashMap, HashSet};
/// # use std::any::TypeId;
/// pub struct MyHashSetGeneric;
/// impl<T: std::hash::Hash + Eq> Generic<T> for MyHashSetGeneric {
///     type Output = HashSet<T>;
/// }
/// assert_eq!(
///     TypeId::of::<HashSet<i32>>(),
///     TypeId::of::<GenericOut<MyHashSetGeneric, i32>>(),
/// );
///
/// pub struct MyHashMapGeneric<Value>(std::marker::PhantomData<Value>);
/// impl<T: std::hash::Hash + Eq, Value> Generic<T> for MyHashMapGeneric<Value> {
///     type Output = HashMap<T, Value>;
/// }
/// assert_eq!(
///     TypeId::of::<HashMap<i32, String>>(),
///     TypeId::of::<GenericOut<MyHashMapGeneric<String>, i32>>(),
/// );
///
/// // Now that we have these wrappers, we can use them to prove the
/// // last two type equalities in the list above:
///
/// fn convert_set<T: std::hash::Hash + Eq>(
///     ev: Witness<impl EqualityProposition<T, i32>>,
/// ) -> Witness<impl EqualityProposition<HashSet<T>, HashSet<i32>>> {
///     ev.with_generic::<MyHashSetGeneric, _, _>()
/// }
/// fn convert_map<T: std::hash::Hash + Eq>(
///     ev: Witness<impl EqualityProposition<T, i32>>,
/// ) -> Witness<impl EqualityProposition<HashMap<T, String>, HashMap<i32, String>>> {
///     ev.with_generic::<MyHashMapGeneric<String>, _, _>()
/// }
/// ```
///
/// Before writing your own [`Generic`] `impl`, check out the [`generics`] module. There are some
/// common [`Generic`] impls pre-written.
pub trait Generic<T: ?Sized> {
    /// What type does the generic output for `T`?
    ///
    /// This is most-easily accessed via [`GenericOut`]
    type Output;
}
/// What's the output of `G<T>`?
pub type GenericOut<G, T> = <G as Generic<T>>::Output;

pub mod generics {
    //! Some helpful types which implement [`Generic`].
    //!
    //! This isn't an exhaustive list, as users can `impl` their own [`Generic`] instances (see the
    //! docs on [`Generic`] for more info).
    use super::*;
    /// `GenericOut<Identity, T> = T`
    pub enum Identity {}
    impl<T> Generic<T> for Identity {
        type Output = T;
    }
    /// `for<'a> GenericOut<Slice<'a>, T> = &'a [T]`
    pub struct Slice<'a>(PhantomData<&'a ()>);
    impl<'a, T: 'a> Generic<T> for Slice<'a> {
        type Output = &'a [T];
    }
    /// `for<'a> GenericOut<SliceMut<'a>, T> = &'a mut [T]`
    pub struct SliceMut<'a>(PhantomData<&'a mut ()>);
    impl<'a, T: 'a> Generic<T> for SliceMut<'a> {
        type Output = &'a mut [T];
    }
    /// `for<'a> GenericOut<RefMut<'a>, T> = &'a mut T`
    pub struct RefMut<'a>(PhantomData<&'a mut ()>);
    impl<'a, T: 'a> Generic<T> for RefMut<'a> {
        type Output = &'a mut T;
    }
    /// `for<'a> GenericOut<Ref<'a>, T> = &'a T`
    pub struct Ref<'a>(PhantomData<&'a ()>);
    impl<'a, T: 'a> Generic<T> for Ref<'a> {
        type Output = &'a T;
    }
    /// Compose [`Generic`]s
    ///
    /// `for<'a> GenericOut<AndThen<A, B>, T> = GenericOut<B, GenericOut<A, T>>`]
    pub struct AndThen<A, B>(PhantomData<(A, B)>);
    impl<T, A: Generic<T>, B: Generic<GenericOut<A, T>>> Generic<T> for AndThen<A, B> {
        type Output = GenericOut<B, GenericOut<A, T>>;
    }
    /// `for<B, T0, T1> GenericOut<RawEitherParty<B, T0, T1>, P> = RawEither<B, P, T0, T1>`
    pub struct RawEitherParty<B: crate::either::raw::EitherBound<T0, T1>, T0, T1>(
        PhantomData<(B, T0, T1)>,
    );
    impl<B: crate::either::raw::EitherBound<T0, T1>, T0, T1, P: crate::GenericParty> Generic<P>
        for RawEitherParty<B, T0, T1>
    {
        type Output = crate::either::raw::RawEither<B, P, T0, T1>;
    }
}

/// A Proposition (logical statement) that purports `T0 == T1`.
///
/// This propositon might be true or false. If it is true (and only if it is true), then a
/// [`Witness`] value can be created. Holding a `Witness<P>` value for some proposition `P`
/// witnesses/is evidence of the fact that `P` is true.
///
/// See [`Witness`] for examples of usage.
pub trait EqualityProposition<T0: ?Sized, T1: ?Sized>:
    sealed::Sealed + 'static + Sized + Copy + Eq + Send + Sync + Ord + std::fmt::Debug + std::hash::Hash
{
    /// The type of a transitive [`EqualityProposition`] that `T0 == T2`, given `T0 == T1` and
    /// `T1 == T2`
    type AndThen<T2: ?Sized, W: EqualityProposition<T1, T2>>: EqualityProposition<T0, T2>;
    /// The type of an [`EqualityProposition`] that `T1 == T0`
    type Sym: EqualityProposition<T1, T0>;
    /// The type of an [`EqualityProposition`] that `GenericOut<G, T0> == GenericOut<G, T1>` given
    /// that `T0 == T1`
    type WithGeneric<G: Generic<T0> + Generic<T1>>: EqualityProposition<GenericOut<G, T0>, GenericOut<G, T1>>;
    /// The type of an [`EqualityProposition`] which is true is `Self` is true or if `P` is true.
    type Disjunction<P: EqualityProposition<T0, T1>>: EqualityProposition<T0, T1>;
    /// If `Self` is true, `SUMMON` is a `Some(Witness)` to that truth. Otherwise it's none.
    ///
    /// # Examples
    /// ```
    /// # use swanky_party2::ty_eq::*;
    /// assert!(<TrueEqualityProposition as EqualityProposition<i32, i32>>::SUMMON.is_some());
    /// assert!(<NotNeccessarilyTrueEqualityProposition as EqualityProposition<i32, String>>::SUMMON.is_none());
    /// ```
    const SUMMON: Option<Witness<Self>>;
    #[doc(hidden)]
    fn cast(witness: Witness<Self>, x: T0) -> T1
    where
        T0: Sized,
        T1: Sized;
}

/// Witness/evidence that the [`EqualityProposition`], `P`, is true.
///
/// Not all [`EqualityProposition`]s are true, but if you have a `Witness<P>` _value_ then you know
/// that `P` is true.
///
/// # Example
/// ```
/// # use swanky_party2::ty_eq::*;
/// fn convert<T>(t: T, w: Witness<impl EqualityProposition<T, i32>>) -> i32 {
///     w.cast(t)
/// }
/// assert_eq!(convert(12, Witness::EQUAL_TYPES), 12);
/// fn cannot_be_called(w: Witness<impl EqualityProposition<i32, String>>) {
///     // It's not possible to obtain a Witness to this proposition (that i32==String) because
///     // it's not true.
///     unreachable!()
/// }
/// ```
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Witness<
    P: 'static
        + Sized
        + Copy
        + Eq
        + Ord
        + Send
        + Sync
        + std::hash::Hash
        + std::fmt::Debug
        + sealed::Sealed,
>(P);
impl Witness<TrueEqualityProposition> {
    /// A witness for situations when Rust knows that two types are equal
    ///
    /// # Example
    /// ```
    /// # use swanky_party2::ty_eq::{Witness, EqualityProposition};
    /// fn t_is_i32<T>(t: T, w: Witness<impl EqualityProposition<T, i32>>) {}
    /// t_is_i32(17_i32, Witness::EQUAL_TYPES);
    /// ```
    pub const EQUAL_TYPES: Self = Witness(TrueEqualityProposition);
}
impl Default for Witness<TrueEqualityProposition> {
    fn default() -> Self {
        Self::EQUAL_TYPES
    }
}
impl<
    P: 'static
        + Sized
        + Copy
        + Eq
        + Ord
        + Send
        + Sync
        + std::hash::Hash
        + std::fmt::Debug
        + sealed::Sealed,
> Witness<P>
{
    /// Convert `T0` into `T1`
    ///
    /// Since `self` witnesses that `T0 == T1`, we can convert from `T0` to `T1`.
    ///
    /// If you want to convert from `T1` into `T0`, call [`self.sym()`](Self::sym), and then call
    /// `.cast()` on that result.
    ///
    /// # Example
    /// ```
    /// # use swanky_party2::ty_eq::{Witness, EqualityProposition};
    /// fn convert<T>(t: T, w: Witness<impl EqualityProposition<T, i32>>) -> i32 {
    ///     w.cast(t)
    /// }
    /// ```
    #[inline(always)]
    pub fn cast<T0, T1>(self, x: T0) -> T1
    where
        P: EqualityProposition<T0, T1>,
    {
        P::cast(self, x)
    }

    /// Turn a witness showing `T0 == T1` into a witness showing `T1 == T0`
    /// # Example
    /// ```compile_fail
    /// # use swanky_party2::ty_eq::{Witness, EqualityProposition};
    /// fn convert<T>(t: T, w: Witness<impl EqualityProposition<i32, T>>) -> i32 {
    ///     // This fails because `w` is setup to convert _from_ i32, not _into_ i32
    ///     w.cast(t)
    /// }
    /// ```
    /// ```
    /// # use swanky_party2::ty_eq::{Witness, EqualityProposition};
    /// fn convert<T>(t: T, w: Witness<impl EqualityProposition<i32, T>>) -> i32 {
    ///     // Using .sym() will swap i32 and T (and turn w into
    ///     // Witness<impl EqualityProposition<T, i32>>)
    ///     w.sym().cast(t)
    /// }
    /// ```
    #[inline(always)]
    pub const fn sym<T0: ?Sized, T1: ?Sized>(self) -> Witness<impl EqualityProposition<T1, T0>>
    where
        P: EqualityProposition<T0, T1>,
    {
        <P::Sym as EqualityProposition<T1, T0>>::SUMMON.unwrap()
    }

    /// Compose witnesses (transitively). Given `T0 == T1` and `T1 == T2`, conclude (produce a
    /// witness showing that) `T0 == T2`.
    ///
    /// # Example
    /// ```
    /// # use swanky_party2::ty_eq::{Witness, EqualityProposition};
    /// fn convert<T0, T1>(
    ///     t: T0,
    ///     w0: Witness<impl EqualityProposition<T0, T1>>,
    ///     w1: Witness<impl EqualityProposition<T1, i32>>,
    /// ) -> i32 {
    ///     w0.and_then(w1).cast(t)
    /// }
    /// ```
    #[inline(always)]
    pub const fn and_then<T0: ?Sized, T1: ?Sized, T2: ?Sized, P2: EqualityProposition<T1, T2>>(
        self,
        w: Witness<P2>,
    ) -> Witness<impl EqualityProposition<T0, T2>>
    where
        P: EqualityProposition<T0, T1>,
    {
        let _ = w;
        <P::AndThen<T2, P2> as EqualityProposition<T0, T2>>::SUMMON.unwrap()
    }

    /// Given `T0 == T1`, witness `G<T0> == G<T1>`
    ///
    /// # Example
    /// ```
    /// # use swanky_party2::ty_eq::*;
    /// // Given that T0 == T1, we can conclude that &'a T0 == &'a T1
    /// fn as_ref<'a, T0: 'a, T1: 'a>(
    ///     w: Witness<impl EqualityProposition<T0, T1>>
    /// ) -> Witness<impl EqualityProposition<&'a T0, &'a T1>> {
    ///     w.with_generic::<generics::Ref, _, _>()
    /// }
    /// ```
    #[inline(always)]
    pub const fn with_generic<G: Generic<T0> + Generic<T1>, T0: ?Sized, T1: ?Sized>(
        self,
    ) -> Witness<impl EqualityProposition<GenericOut<G, T0>, GenericOut<G, T1>>>
    where
        P: EqualityProposition<T0, T1>,
    {
        <P::WithGeneric<G> as EqualityProposition<_, _>>::SUMMON.unwrap()
    }

    /// Turn `self` into the left-branch of a disjunction.
    ///
    /// See [`JoinedTypeEqualityWitness`] for more details.
    #[inline(always)]
    pub const fn join_left<T0, T1, P2: EqualityProposition<T0, T1>>(
        self,
    ) -> JoinedTypeEqualityWitness<P, P2>
    where
        P: EqualityProposition<T0, T1>,
    {
        JoinedTypeEqualityWitness(PhantomData)
    }

    /// Turn `self` into the right-branch of a disjunction.
    ///
    /// See [`JoinedTypeEqualityWitness`] for more details.
    #[inline(always)]
    pub const fn join_right<T0, T1, P2: EqualityProposition<T0, T1>>(
        self,
    ) -> JoinedTypeEqualityWitness<P2, P>
    where
        P: EqualityProposition<T0, T1>,
    {
        JoinedTypeEqualityWitness(PhantomData)
    }
}

/// [`EqualityProposition`] disjunction utility
///
/// Consider the following code:
/// ```compile_fail
/// # use swanky_party2::ty_eq::*;
/// enum Foo<A, B> {
///     A(A),
///     B(B),
/// }
/// fn disjunction<T0, T1>(
///     f: Foo<
///         Witness<impl EqualityProposition<T0, T1>>,
///         Witness<impl EqualityProposition<T0, T1>>
///     >,
/// ) -> Witness<impl EqualityProposition<T0, T1>> {
///     // we know that f contains _a_ valid witness to T0 == T1, we just want to return it
///     match f {
///         Foo::A(a) => a,
///         Foo::B(b) => b,
///     }
/// }
/// ```
///
/// If we try to run the above code, then Rust will complain that it can't figure out what the type
/// of the return value should be. Should it be the type of the proposition for `A`? Or the type of
/// the proposition for `B`?
///
/// What we want is a way to return proposition `A` or proposition `B`. Or, alternatively phrased,
/// we want to be able to _join_ `A` and `B` together.
///
/// That's where [`Witness::join_left`] and [`Witness::join_right`] come in.
///
/// ```
/// # use swanky_party2::ty_eq::*;
/// enum Foo<A, B> {
///     A(A),
///     B(B),
/// }
/// fn disjunction<T0, T1>(
///     f: Foo<
///         Witness<impl EqualityProposition<T0, T1>>,
///         Witness<impl EqualityProposition<T0, T1>>
///     >,
/// ) -> Witness<impl EqualityProposition<T0, T1>> {
///     // we know that f contains _a_ valid witness to T0 == T1, we just want to return it
///     match f {
///         Foo::A(a) => a.join_left().join(),
///         Foo::B(b) => b.join_right().join(),
///     }
/// }
/// ```
///
/// But putting `.join_left().join()` on one branch and `.join_right().join()` on the other, we
/// give Rust a _single_ proposition output type: the type returned by `.join()`.
///
/// You shouldn't ever have to manipulate [`JoinedTypeEqualityWitness`] directly, or do anything
/// aside from call `.join()` on it. (It exists separate from `.join_left()` and `.join_right()`
/// to make the Rust type inference work out.)
#[derive(Clone, Copy)]
pub struct JoinedTypeEqualityWitness<
    Left: 'static + Sized + Copy + Eq + std::fmt::Debug + sealed::Sealed,
    Right: 'static + Sized + Copy + Eq + std::fmt::Debug + sealed::Sealed,
>(PhantomData<(Left, Right)>);
impl<
    Left: 'static + Sized + Copy + Eq + std::fmt::Debug + sealed::Sealed,
    Right: 'static + Sized + Copy + Eq + std::fmt::Debug + sealed::Sealed,
> JoinedTypeEqualityWitness<Left, Right>
{
    /// Conclude that `T0 == T1` given that `Left` or `Right` is true
    ///
    /// See the docs for [`JoinedTypeEqualityWitness`] for more details
    #[inline(always)]
    pub const fn join<T0: ?Sized, T1: ?Sized>(self) -> Witness<impl EqualityProposition<T0, T1>>
    where
        Left: EqualityProposition<T0, T1>,
        Right: EqualityProposition<T0, T1>,
    {
        <Left::Disjunction<Right> as EqualityProposition<T0, T1>>::SUMMON.unwrap()
    }
}

/// An [`EqualityProposition`] which is _true_.
///
/// That is, an [`EqualityProposition`] between two equal types.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct TrueEqualityProposition;
impl sealed::Sealed for TrueEqualityProposition {}
impl<T: ?Sized> EqualityProposition<T, T> for TrueEqualityProposition {
    type AndThen<T2: ?Sized, W: EqualityProposition<T, T2>> = W;
    type Sym = Self;
    type WithGeneric<G: Generic<T>> = TrueEqualityProposition;
    type Disjunction<P: EqualityProposition<T, T>> = TrueEqualityProposition;
    const SUMMON: Option<Witness<Self>> = Some(Witness::EQUAL_TYPES);

    #[inline(always)]
    fn cast(_witness: Witness<Self>, x: T) -> T
    where
        T: Sized,
    {
        x
    }
}

/// A utility trait for indicating that `Self == T`
///
/// # Example
/// ```
/// # use swanky_party2::ty_eq::IsSameType;
/// fn foo<T: IsSameType<U>, U>(t: T, u: U) {}
/// foo(String::new(), String::new());
/// ```
/// ```compile_fail
/// # use swanky_party2::ty_eq::IsSameType;
/// # fn foo<T: IsSameType<U>, U>(t: T, u: U) {}
/// foo(String::new(), 12);
/// ```
pub trait IsSameType<T>: From<T> + Into<T> {
    /// The [`EqualityProposition`] that `Self == T`
    type EqualityProposition: EqualityProposition<Self, T>;
    /// A [`Witness`] that `Self == T`
    ///
    /// # Example
    /// ```
    /// # use swanky_party2::ty_eq::*;
    /// fn foo<T: IsSameType<U>, U>(t: T) -> U {
    ///     T::WITNESS.cast(t)
    /// }
    /// ```
    const WITNESS: Witness<Self::EqualityProposition>;
}
impl<T> IsSameType<T> for T {
    type EqualityProposition = TrueEqualityProposition;
    const WITNESS: Witness<Self::EqualityProposition> = Witness::EQUAL_TYPES;
}

/// An [`EqualityProposition`] which might not be true (but in practice isn't).
///
/// This [`EqualityProposition`] is an uninhabitied type, and it's impossible to get a witness for
/// this proposition. Thus, we can use it in situations where an equality does not hold.
///
/// ```
/// # use swanky_party2::ty_eq::*;
/// fn foo<P: EqualityProposition<i32, String>>() {}
/// foo::<NotNeccessarilyTrueEqualityProposition>();
/// ```
///
/// This is totally safe, since there's no way to get a
/// [`Witness<NotNeccessarilyTrueEqualityProposition>`](Witness).
///
/// `NotNeccessarilyTrueEqualityProposition` is so-named because we cannot prevent you from
/// provding a `NotNeccessarilyTrueEqualityProposition` for equal types.
///
/// ```
/// # use swanky_party2::ty_eq::*;
/// fn foo<P: EqualityProposition<i32, i32>>() {}
/// foo::<NotNeccessarilyTrueEqualityProposition>();
/// ```
///
/// This doesn't matter in practice, because we don't depend on type _inequality_ (using the
/// `ty_eq` module).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum NotNeccessarilyTrueEqualityProposition {}
impl sealed::Sealed for NotNeccessarilyTrueEqualityProposition {}
impl<T0: ?Sized, T1: ?Sized> EqualityProposition<T0, T1>
    for NotNeccessarilyTrueEqualityProposition
{
    type AndThen<T2: ?Sized, W: EqualityProposition<T1, T2>> = Self;
    type Sym = Self;
    type WithGeneric<G: Generic<T0> + Generic<T1>> = NotNeccessarilyTrueEqualityProposition;
    type Disjunction<P: EqualityProposition<T0, T1>> = P;
    const SUMMON: Option<Witness<Self>> = None;
    fn cast(_witness: Witness<Self>, _x: T0) -> T1
    where
        T0: Sized,
        T1: Sized,
    {
        unreachable!()
    }
}
