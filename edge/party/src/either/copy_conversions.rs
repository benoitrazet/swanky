use bytemuck::TransparentWrapper;

use crate::{
    GenericParty,
    either::raw::{RawEither, bounds},
    either::{PartyEither, PartyEitherCopy},
    ty_eq::{IsSameType, generics},
};

impl<P: GenericParty, T0: Copy, T1: Copy> From<PartyEitherCopy<P, T0, T1>>
    for PartyEither<P, T0, T1>
{
    #[inline(always)]
    fn from(value: PartyEitherCopy<P, T0, T1>) -> Self {
        Self(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
            }
            .cast(value.0),
        )
    }
}
impl<P: GenericParty, T0: Copy, T1: Copy> From<PartyEither<P, T0, T1>>
    for PartyEitherCopy<P, T0, T1>
{
    #[inline(always)]
    fn from(value: PartyEither<P, T0, T1>) -> Self {
        Self(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
                    .sym()
            }
            .cast(value.0),
        )
    }
}
impl<'a, P: GenericParty, T0: Copy, T1: Copy> From<&'a PartyEitherCopy<P, T0, T1>>
    for &'a PartyEither<P, T0, T1>
{
    #[inline(always)]
    fn from(value: &'a PartyEitherCopy<P, T0, T1>) -> Self {
        TransparentWrapper::wrap_ref(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
                    .with_generic::<generics::Ref, _, _>()
            }
            .cast(&value.0),
        )
    }
}
impl<'a, P: GenericParty, T0: Copy, T1: Copy> From<&'a PartyEither<P, T0, T1>>
    for &'a PartyEitherCopy<P, T0, T1>
{
    #[inline(always)]
    fn from(value: &'a PartyEither<P, T0, T1>) -> Self {
        TransparentWrapper::wrap_ref(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
                    .sym()
                    .with_generic::<generics::Ref, _, _>()
            }
            .cast(&value.0),
        )
    }
}
impl<'a, P: GenericParty, T0: Copy, T1: Copy> From<&'a mut PartyEitherCopy<P, T0, T1>>
    for &'a mut PartyEither<P, T0, T1>
{
    #[inline(always)]
    fn from(value: &'a mut PartyEitherCopy<P, T0, T1>) -> Self {
        TransparentWrapper::wrap_mut(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
                    .with_generic::<generics::RefMut, _, _>()
            }
            .cast(&mut value.0),
        )
    }
}
impl<'a, P: GenericParty, T0: Copy, T1: Copy> From<&'a mut PartyEither<P, T0, T1>>
    for &'a mut PartyEitherCopy<P, T0, T1>
{
    #[inline(always)]
    fn from(value: &'a mut PartyEither<P, T0, T1>) -> Self {
        TransparentWrapper::wrap_mut(
            const {
                <RawEither<bounds::Copy, P, T0, T1> as IsSameType<
                    RawEither<bounds::Any, P, T0, T1>,
                >>::WITNESS
                    .sym()
                    .with_generic::<generics::RefMut, _, _>()
            }
            .cast(&mut value.0),
        )
    }
}

// TODO: we can do this for more containers.
