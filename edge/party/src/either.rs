//! Party-based type selection.
//!
//! This module implements the [`PartyEither`] (and
//! [`PartyEitherCopy`]) types, which provide an efficient way to
//! wrap data whose type is dependent on which participant in a
//! protocol is running the code.
//!
//! The type `PartyEither<P: GenericParty, T0, T1>` is
//! `repr(transparent)` to `T0` if `P` is the system's `Party0`, and
//! `repr(transparent)` to `T1` if `P` is the system's `Party1`.
//! In practice, this means that `PartyEither` acts as a newtype
//! wrapper for `T0` _or_ `T1`, depending on which protocol
//! participant is executing.
//!
//! See the [`crate`] documentation for basic usage examples in
//! context.
//!
//! These types are based on [`RawEither`], which is _actually equal_
//! to the underlying type; see [`raw`] for additional detail on this
//! type, which is not needed in typical cases.
use crate::ty_eq::{EqualityProposition as EqProp, Witness, generics};
use crate::{GenericParty, GenericWhichParty};
use bytemuck::TransparentWrapper;
use raw::{RawEither, bounds, either_type_substitution};
use std::{
    fmt::Debug,
    io::{Read, Write},
};

pub mod raw;

macro_rules! either {
    ($(
        $(#[$meta:meta])*
        type $PartyEither:ident$(: $Copy:ident)? => $bound:ty;
    )*) => {$(
        #[repr(transparent)]
        #[derive(TransparentWrapper)]
        #[doc=concat!(
            "`", stringify!($PartyEither), "` is a wrapper type which is `repr(transparent)` to `T0` ",
            "if `P == Party0`, else it's `repr(transparent)` to `T1`",
            "\n\n"
        )]
        $(#[$meta])*
        pub struct $PartyEither<P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>(
            RawEither<$bound, P, T0, T1>
        );
        impl<P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?> $PartyEither<P, T0, T1> {
            /// Construct a new [`PartyEither`] containing `x`, given that `P == P2`
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// let alice_variant: PartyEither<Alice, String, i32> =
            ///     PartyEither::new::<Alice>(Witness::EQUAL_TYPES, "Hello!".to_string());
            /// let bob_variant: PartyEither<Bob, String, i32> =
            ///     PartyEither::new::<Bob>(Witness::EQUAL_TYPES, 150);
            /// fn make_either<P: Party>() -> PartyEither<P, String, i32> {
            ///     match P::WHICH {
            ///         WhichParty::Alice(e) =>
            ///             PartyEither::new::<Alice>(e, "I'm alice!".to_string()),
            ///         WhichParty::Bob(e) =>
            ///             PartyEither::new::<Bob>(e, 143),
            ///     }
            /// }
            /// ```
            #[inline(always)]
            pub fn new<P2: GenericParty>(
                ev: Witness<impl EqProp<P, P2>>,
                x: RawEither<$bound, P2, T0, T1>,
            ) -> Self {
                Self(
                    ev.sym()
                        .with_generic::<generics::RawEitherParty<$bound, T0, T1>, _, _>()
                        .cast(x)
                )
            }
            /// Extract the value of a [`PartyEither`], given that `P == P2`
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// let alice_variant: PartyEither<Alice, String, i32> =
            ///     PartyEither::new::<Alice>(Witness::EQUAL_TYPES, "Hello!".to_string());
            /// assert_eq!(alice_variant.into_inner(Witness::EQUAL_TYPES), "Hello!".to_string());
            /// let bob_variant: PartyEither<Bob, String, i32> =
            ///     PartyEither::new::<Bob>(Witness::EQUAL_TYPES, 150);
            /// assert_eq!(bob_variant.into_inner(Witness::EQUAL_TYPES), 150);
            /// ```
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// # party_system! {
            /// #     mod ps {
            /// #         Alice,
            /// #         Bob,
            /// #     }
            /// # }
            /// # use ps::*;
            /// # let alice_variant: PartyEither<Alice, String, i32> =
            /// #     PartyEither::new::<Alice>(Witness::EQUAL_TYPES, "Hello!".to_string());
            /// # let bob_variant: PartyEither<Bob, String, i32> =
            /// #     PartyEither::new::<Bob>(Witness::EQUAL_TYPES, 150);
            /// fn format_either<P: Party>(x: PartyEither<P, String, i32>) -> String {
            ///     match P::WHICH {
            ///         WhichParty::Alice(e) =>
            ///             format!("Alice says: {}", x.into_inner::<Alice>(e)),
            ///         WhichParty::Bob(e) =>
            ///             format!("Bob says: {}", x.into_inner::<Bob>(e)),
            ///     }
            /// }
            /// assert_eq!(format_either(alice_variant), "Alice says: Hello!".to_string());
            /// assert_eq!(format_either(bob_variant), "Bob says: 150".to_string());
            /// ```
            #[inline(always)]
            pub fn into_inner<P2: GenericParty>(
                self,
                ev: Witness<impl EqProp<P, P2>>
            ) -> RawEither<$bound, P2, T0, T1> {
                ev.with_generic::<generics::RawEitherParty<$bound, T0, T1>, _, _>().cast(self.0)
            }
            /// Create a new [`PartyEither`] by running `map0` on the either contents if `P ==
            /// Party0`, and running `map1` on the either contents, otherwise.
            ///
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// let alice_variant: PartyEither<Alice, String, i32> =
            ///     PartyEither::new::<Alice>(Witness::EQUAL_TYPES, "Hello!".to_string());
            /// let bob_variant: PartyEither<Bob, String, i32> =
            ///     PartyEither::new::<Bob>(Witness::EQUAL_TYPES, 150);
            /// fn do_it<P: Party>(e: PartyEither<P, String, i32>) -> PartyEither<P, usize, i32> {
            ///     e.map(|str| str.len(), |i| i * 2)
            /// }
            /// assert_eq!(do_it(alice_variant), PartyEither::new(Witness::EQUAL_TYPES, 6));
            /// assert_eq!(do_it(bob_variant), PartyEither::new(Witness::EQUAL_TYPES, 300));
            /// ```
            #[inline(always)]
            pub fn map<U0$(: $Copy)?, U1$(: $Copy)?>(
                self,
                map0: impl FnOnce(T0) -> U0,
                map1: impl FnOnce(T1) -> U1,
            ) -> $PartyEither<P, U0, U1> {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) =>
                        $PartyEither::new(ev, map0(self.into_inner(ev))),
                    GenericWhichParty::Party1(ev) =>
                        $PartyEither::new(ev, map1(self.into_inner(ev))),
                }
            }
            /// Convert from `&PartyEither<P, A, B>` into `PartyEither<P, &A, &B>`
            ///
            /// This serves the same purpose as [`Option::as_ref`]
            ///
            /// This is frequently useful to _borrow_ the contents of a `PartyEither`.
            /// ```compile_fail
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// fn len<P: Party>(x: &PartyEither<P, String, Vec<u64>>) -> usize {
            ///     // It's easier to write this with .map(), but it's more illustrative to write
            ///     // this manually :)
            ///     match P::WHICH {
            ///         WhichParty::Alice(ev) => {
            ///             // Rust is going to complain right here!
            ///             // x is only have a _reference_ to a String, so we want a &String
            ///             // to come out of it, not a String
            ///             let alice: String = x.into_inner(ev);
            ///             alice.len()
            ///         }
            ///         WhichParty::Bob(ev) => {
            ///             // And we run into the same problem with bob
            ///             let bob: Vec<u64> = x.into_inner(ev);
            ///             bob.len()
            ///         }
            ///     }
            /// }
            /// ```
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// # party_system! {
            /// #     mod ps {
            /// #         Alice,
            /// #         Bob,
            /// #     }
            /// # }
            /// # use ps::*;
            /// fn len1<P: Party>(x: &PartyEither<P, String, Vec<u64>>) -> usize {
            ///     // .as_ref() moves the references to the inside (it's now an either of
            ///     // references)
            ///     let x_ref: PartyEither<P, &String, &Vec<u64>> = x.as_ref();
            ///     match P::WHICH {
            ///         WhichParty::Alice(ev) => {
            ///             // We've now fixed our reference issue!
            ///             let alice: &String = x_ref.into_inner(ev);
            ///             alice.len()
            ///         }
            ///         WhichParty::Bob(ev) => {
            ///             let bob: &Vec<u64> = x_ref.into_inner(ev);
            ///             bob.len()
            ///         }
            ///     }
            /// }
            /// // We don't actually need all these variables and type annotations
            /// fn len2<P: Party>(x: &PartyEither<P, String, Vec<u64>>) -> usize {
            ///     match P::WHICH {
            ///         WhichParty::Alice(ev) => x.as_ref().into_inner(ev).len(),
            ///         WhichParty::Bob(ev) => x.as_ref().into_inner(ev).len(),
            ///     }
            /// }
            /// // And, if we use .map(), we don't even need a match statement
            /// fn len3<P: Party>(x: &PartyEither<P, String, Vec<u64>>) -> usize {
            ///     x.as_ref().map(|a| a.len(), |b| b.len()).into_inner_same()
            /// }
            /// ```
            #[inline(always)]
            pub fn as_ref<'a>(&'a self) -> $PartyEither<P, &'a T0, &'a T1> {
                $PartyEither(const { either_type_substitution::<
                    generics::Ref<'a>,
                    $bound,
                    $bound,
                    P,
                    T0,
                    T1,
                >() }.cast(&self.0))
            }
            /// Convert from `&mut PartyEither<P, A, B>` into
            /// `PartyEither<P, &mut A, &mut B>`
            ///
            /// This serves the same purpose as [`Option::as_mut`]
            ///
            /// Otherwise functions much like [`PartyEither::as_ref`]
            #[inline(always)]
            pub fn as_mut<'a>(&'a mut self) -> PartyEither<P, &'a mut T0, &'a mut T1> {
                PartyEither(const { either_type_substitution::<
                    generics::RefMut<'a>,
                    $bound,
                    bounds::Any,
                    P,
                    T0,
                    T1,
                >() }.cast(&mut self.0))
            }
            /// Combine `self` with another `PartyEither` by zipping them
            ///
            /// Compare to [`Option::zip`]
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// fn combine<P: Party>(
            ///     a: PartyEither<P, String, u16>,
            ///     b: PartyEither<P, std::net::Ipv4Addr, u128>
            /// ) -> PartyEither<P, (String, std::net::Ipv4Addr), (u16, u128)> {
            ///     a.zip(b)
            /// }
            /// assert_eq!(
            ///     combine::<Alice>(
            ///         PartyEither::new(Witness::EQUAL_TYPES, "Alice".to_string()),
            ///         PartyEither::new(Witness::EQUAL_TYPES, std::net::Ipv4Addr::LOCALHOST),
            ///     ).into_inner(Witness::EQUAL_TYPES),
            ///     ("Alice".to_string(), std::net::Ipv4Addr::LOCALHOST),
            /// );
            /// assert_eq!(
            ///     combine::<Bob>(
            ///         PartyEither::new(Witness::EQUAL_TYPES, 1),
            ///         PartyEither::new(Witness::EQUAL_TYPES, 2),
            ///     ).into_inner(Witness::EQUAL_TYPES),
            ///     (1, 2),
            /// );
            /// ```
            #[inline(always)]
            pub fn zip<
                T0x$(: $Copy)?,
                T1x$(: $Copy)?,
            >(self, x: $PartyEither<P, T0x, T1x>) -> $PartyEither<P, (T0, T0x), (T1, T1x)> {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) =>
                        $PartyEither::new(ev, (self.into_inner(ev), x.into_inner(ev))),
                    GenericWhichParty::Party1(ev) =>
                        $PartyEither::new(ev, (self.into_inner(ev), x.into_inner(ev))),
                }
            }

            /// Combine `self` with another `PartyEither` by zipping them with `map0`/`map1`
            ///
            /// Compare to [`Option::zip_with`]
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// fn combine<P: Party>(
            ///     a: PartyEither<P, String, u16>,
            ///     b: PartyEither<P, std::net::Ipv4Addr, u128>
            /// ) -> PartyEither<P, String, u128> {
            ///     // Let's combine these eithers in an arbitrary way!
            ///     a.zip_with(
            ///         b,
            ///         |a, b| format!("{a} with addr {b}"),
            ///         |a, b| u128::from(a) + b,
            ///     )
            /// }
            /// assert_eq!(
            ///     combine::<Alice>(
            ///         PartyEither::new(Witness::EQUAL_TYPES, "Alice".to_string()),
            ///         PartyEither::new(Witness::EQUAL_TYPES, std::net::Ipv4Addr::LOCALHOST),
            ///     ).into_inner(Witness::EQUAL_TYPES),
            ///     "Alice with addr 127.0.0.1".to_string(),
            /// );
            /// assert_eq!(
            ///     combine::<Bob>(
            ///         PartyEither::new(Witness::EQUAL_TYPES, 1),
            ///         PartyEither::new(Witness::EQUAL_TYPES, 2),
            ///     ).into_inner(Witness::EQUAL_TYPES),
            ///     3,
            /// );
            /// ```
            #[inline(always)]
            pub fn zip_with<
                T0x$(: $Copy)?,
                T1x$(: $Copy)?,
                U0$(: $Copy)?,
                U1$(: $Copy)?,
            >(
                self,
                x: $PartyEither<P, T0x, T1x>,
                map0: impl FnOnce(T0, T0x) -> U0,
                map1: impl FnOnce(T1, T1x) -> U1,
            ) -> $PartyEither<P, U0, U1> {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) =>
                        $PartyEither::new(ev, map0(self.into_inner(ev), x.into_inner(ev))),
                    GenericWhichParty::Party1(ev) =>
                        $PartyEither::new(ev, map1(self.into_inner(ev), x.into_inner(ev))),
                }
            }
        }

        impl<'a, P: GenericParty, T0 $(: $Copy)?, T1 $(: $Copy)?> $PartyEither<P, &'a [T0], &'a [T1]> {
            /// Convert a slice of `PartyEither` to a `PartyEither` of
            /// slices.
            pub fn pull_either_outside(slice: &'a [$PartyEither<P, T0, T1>]) -> Self {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(e) => {
                        Self::new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const T0,
                                slice.len()
                            )
                        })
                    }
                    GenericWhichParty::Party1(e) => {
                        Self::new(e, unsafe {
                            std::slice::from_raw_parts(
                                slice.as_ptr() as *const T1,
                                slice.len()
                            )
                        })
                    }
                }
            }
        }

        impl<P: GenericParty, T0: Default$(+ $Copy)?, T1: Default$(+ $Copy)?>
            Default for $PartyEither<P, T0, T1>
        {
            #[inline(always)]
            fn default() -> Self {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) => Self::new(ev, T0::default()),
                    GenericWhichParty::Party1(ev) => Self::new(ev, T1::default()),
                }
            }
        }
        impl<P: GenericParty, T0: Debug$(+ $Copy)?, T1: Debug$(+ $Copy)?>
            Debug for $PartyEither<P, T0, T1>
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) =>
                        f.debug_tuple(std::any::type_name::<P>())
                            .field(self.as_ref().into_inner(ev))
                            .finish(),
                    GenericWhichParty::Party1(ev) =>
                        f.debug_tuple(std::any::type_name::<P>())
                            .field(self.as_ref().into_inner(ev))
                            .finish(),
                }
            }
        }
        impl<P: GenericParty, T$(: $Copy)?> $PartyEither<P, T, T> {
            /// If both sides of the either have the same type, we can convert the either to that
            /// type.
            ///
            /// # Example
            /// ```
            /// # use swanky_party::{*, either::*, ty_eq::Witness};
            /// party_system! {
            ///     mod ps {
            ///         Alice,
            ///         Bob,
            ///     }
            /// }
            /// use ps::*;
            /// let alice_variant: PartyEither<Alice, String, String> =
            ///     PartyEither::new::<Alice>(Witness::EQUAL_TYPES, "Hello!".to_string());
            /// let either: String = alice_variant.into_inner_same();
            /// assert_eq!(either, "Hello!".to_string());
            /// ```
            #[inline(always)]
            pub fn into_inner_same(self) -> T {
                match P::GENERIC_WHICH {
                    GenericWhichParty::Party0(ev) => self.into_inner(ev),
                    GenericWhichParty::Party1(ev) => self.into_inner(ev),
                }
            }
        }
        impl<P: GenericParty, T0: PartialEq$(+ $Copy)?, T1: PartialEq$(+ $Copy)?>
            PartialEq for $PartyEither<P, T0, T1>
        {
            #[inline(always)]
            fn eq(&self, other: &Self) -> bool {
                self.as_ref()
                    .zip(other.as_ref())
                    .map(|(a, b)| a.eq(b), |(a, b)| a.eq(b))
                    .into_inner_same()
            }
        }
        impl<P: GenericParty, T0: Eq$(+ $Copy)?, T1: Eq$(+ $Copy)?>
            Eq for $PartyEither<P, T0, T1>
        {}
        unsafe impl<P: GenericParty, T0: Send$(+ $Copy)?, T1: Send$(+ $Copy)?>
            Send for $PartyEither<P, T0, T1>
        {}
        unsafe impl<P: GenericParty, T0: Sync$(+ $Copy)?, T1: Sync$(+ $Copy)?>
            Sync for $PartyEither<P, T0, T1>
        {}
        impl<'a, P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>
            From<&'a $PartyEither<P, T0, T1>> for $PartyEither<P, &'a T0, &'a T1>
        {
            #[inline(always)]
            fn from(x: &'a $PartyEither<P, T0, T1>) -> Self {
                x.as_ref()
            }
        }
        impl<'a, P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>
            From<&'a mut $PartyEither<P, T0, T1>> for PartyEither<P, &'a mut T0, &'a mut T1>
        {
            #[inline(always)]
            fn from(x: &'a mut $PartyEither<P, T0, T1>) -> Self {
                x.as_mut()
            }
        }
        impl<'a, P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>
            From<$PartyEither<P, &'a T0, &'a T1>> for &'a $PartyEither<P, T0, T1>
        {
            #[inline(always)]
            fn from(x: $PartyEither<P, &'a T0, &'a T1>) -> Self {
                TransparentWrapper::wrap_ref(const { either_type_substitution::<
                    generics::Ref<'a>,
                    $bound,
                    $bound,
                    P,
                    T0,
                    T1,
                >().sym() }.cast(x.0))
            }
        }
        impl<'a, P: GenericParty, T0$(: $Copy)?, T1$(: $Copy)?>
            From<PartyEither<P, &'a mut T0, &'a mut T1>> for &'a mut $PartyEither<P, T0, T1>
        {
            #[inline(always)]
            fn from(x: PartyEither<P, &'a mut T0, &'a mut T1>) -> Self {
                TransparentWrapper::wrap_mut(const { either_type_substitution::<
                    generics::RefMut<'a>,
                    $bound,
                    bounds::Any,
                    P,
                    T0,
                    T1,
                >().sym() }.cast(x.0))
            }
        }
    )*};
}

impl<P: GenericParty, T0: Copy, T1: Copy> Clone for PartyEitherCopy<P, T0, T1> {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}
impl<P: GenericParty, T0: Copy, T1: Copy> Copy for PartyEitherCopy<P, T0, T1> {}

impl<P: GenericParty, T0: Clone, T1: Clone> Clone for PartyEither<P, T0, T1> {
    #[inline(always)]
    fn clone(&self) -> Self {
        self.as_ref().map(Clone::clone, Clone::clone)
    }
}

either! {
    type PartyEither => bounds::Any;
    /// # Copy
    /// [`PartyEitherCopy`] is identical to [`PartyEither`] except that it implements [`Copy`] (and
    /// correspondingly requires `T0` and `T1` to implement `Copy`, too).
    ///
    /// To convert between [`PartyEitherCopy`] and [`PartyEither`], you can use [`From::from`].
    ///
    /// ```
    /// # use swanky_party::{*, either::*};
    /// party_system! {
    ///     mod ps {
    ///         Alice,
    ///         Bob,
    ///     }
    /// }
    /// use ps::*;
    /// fn convert<P: Party>(e: PartyEither<P, i32, bool>) -> PartyEitherCopy<P, i32, bool> {
    ///     e.into()
    /// }
    /// ```
    type PartyEitherCopy: Copy => bounds::Copy;
}

impl<P: GenericParty, W0: Write, W1: Write> Write for PartyEither<P, W0, W1> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => self.as_mut().into_inner(e).write(buf),
            GenericWhichParty::Party1(e) => self.as_mut().into_inner(e).write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => self.as_mut().into_inner(e).flush(),
            GenericWhichParty::Party1(e) => self.as_mut().into_inner(e).flush(),
        }
    }
}

impl<P: GenericParty, R0: Read, R1: Read> Read for PartyEither<P, R0, R1> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match P::GENERIC_WHICH {
            GenericWhichParty::Party0(e) => self.as_mut().into_inner(e).read(buf),
            GenericWhichParty::Party1(e) => self.as_mut().into_inner(e).read(buf),
        }
    }
}

mod copy_conversions;
mod impls;
