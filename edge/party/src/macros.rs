/// Define a new [`PartySystem`](crate::PartySystem)
///
/// # Example
/// ```
/// swanky_party::party_system! {
///     pub mod oblivious_transfer_parties {
///         /// This party gives out 2 values
///         Sender,
///         /// This party only gets one value
///         Receiver,
///     }
/// }
/// ```
///
/// This expands into
///
/// ```ignore
/// pub mod oblivious_transfer_parties {
///     pub struct Sender;
///     pub struct Receiver;
///     pub struct PartySystem;
///     pub enum WhichParty<P: Party> {
///         Sender(Witness<impl EqualityProposition<P, Sender>>),
///         Receiver(Witness<impl EqualityProposition<P, Receiver>>),
///     }
///     pub trait Party: GenericParty<PartySystem = PartySystem> {
///         const WHICH: WhichParty<Self>;
///         /* ... */
///     }
///     impl Party for Sender { /* ... */ }
///     impl Party for Receiver { /* ... */ }
/// }
/// ```
#[macro_export]
macro_rules! party_system {
    ($vis:vis mod $parties_name:ident {
        $(#[$meta0:meta])*
        $party0:ident,
        $(#[$meta1:meta])*
        $party1:ident $(,)?
    }) => {
        $vis mod $parties_name {
            #![doc = concat!(
                "Party definitions for [`", stringify!($party0), "`] and ",
                "[`", stringify!($party1), "`]"
            )]
            use $crate::{self as swanky_party};
            use swanky_party::{ty_eq::Witness};
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
            #[doc = concat!(
                "Evidence that `P` is [`", stringify!($party0), "`] or ",
                "[`", stringify!($party1), "`]"
            )]
            pub enum WhichParty<P: Party> {
                #[doc = concat!(
                    "Evidence that `P` is [`", stringify!($party0), "`]"
                )]
                $party0(Witness<P::IsParty0>),
                #[doc = concat!(
                    "Evidence that `P` is [`", stringify!($party1), "`]"
                )]
                $party1(Witness<P::IsParty1>),
            }
            $(#[$meta0])*
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
            pub struct $party0;
            $(#[$meta1])*
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
            pub struct $party1;
            #[doc = concat!(
                "A [`PartySystem`](swanky_party::PartySystem) for ",
                stringify!($party0 and $party1),
            )]
            #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
            pub struct PartySystem;
            /// A trait alias for a `GenericParty` where the party system is [`PartySystem`].
            pub trait Party: $crate::GenericParty<PartySystem=PartySystem> {
                /// Which party is `Self`?
                /// Unlike `GenericWhichParty`
                #[doc = concat!(
                    "Which party is `Self`?\n\n",
                    "Unlike [`GenericParty::GENERIC_WHICH`](swanky_party::GenericParty::GENERIC_WHICH) ",
                    "This `WHICH` is of type [`WhichParty`], which uses enum variants: ",
                    "`", stringify!($party0), "` and ",
                    "`", stringify!($party1), "`, rather than generic names.",
                )]
                const WHICH: WhichParty<Self>;
            }
            impl<P: $crate::GenericParty<PartySystem=PartySystem>> Party for P {
                const WHICH: WhichParty<Self> = match P::GENERIC_WHICH {
                    $crate::GenericWhichParty::Party0(proof) => WhichParty::$party0(proof),
                    $crate::GenericWhichParty::Party1(proof) => WhichParty::$party1(proof),
                };
            }
            impl $crate::PartySystem for PartySystem {
                type WhichParty<P: $crate::GenericParty<PartySystem = Self>> = WhichParty<P>;
                type Party0 = $party0;
                type Party1 = $party1;
            }
            impl $crate::GenericParty for $party0 {
                type IsParty0 = $crate::ty_eq::TrueEqualityProposition;
                type IsParty1 = $crate::ty_eq::NotNeccessarilyTrueEqualityProposition;

                type PartySystem = PartySystem;
                const GENERIC_WHICH: $crate::GenericWhichParty<Self> =
                    $crate::GenericWhichParty::Party0($crate::ty_eq::Witness::EQUAL_TYPES);
                type RawImpl = $crate::__macro_internal::Party0Impl;
            }
            impl $crate::GenericParty for $party1 {
                type IsParty0 = $crate::ty_eq::NotNeccessarilyTrueEqualityProposition;
                type IsParty1 = $crate::ty_eq::TrueEqualityProposition;

                type PartySystem = PartySystem;
                const GENERIC_WHICH: $crate::GenericWhichParty<Self> =
                    $crate::GenericWhichParty::Party1($crate::ty_eq::Witness::EQUAL_TYPES);
                type RawImpl = $crate::__macro_internal::Party1Impl;
            }
            impl<P: Party> From<$crate::GenericWhichParty<P>> for WhichParty<P> {
                #[inline]
                fn from(w: $crate::GenericWhichParty<P>) -> Self {
                    match w {
                        $crate::GenericWhichParty::Party0(ev) => WhichParty::$party0(ev),
                        $crate::GenericWhichParty::Party1(ev) => WhichParty::$party1(ev),
                    }
                }
            }
            impl<P: Party> Into<$crate::GenericWhichParty<P>> for WhichParty<P> {
                #[inline]
                fn into(self) -> $crate::GenericWhichParty<P> {
                    match self {
                        WhichParty::$party0(ev) => $crate::GenericWhichParty::Party0(ev),
                        WhichParty::$party1(ev) => $crate::GenericWhichParty::Party1(ev),
                    }
                }
            }
        }
    };
}

#[doc(hidden)]
pub mod __macro_internal {
    pub use crate::either::raw::internal::{Party0Impl, Party1Impl};
}
