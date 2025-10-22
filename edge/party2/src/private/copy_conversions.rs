use bytemuck::TransparentWrapper;

use crate::{
    GenericParty,
    either::raw::bounds,
    private::{
        PartyPrivate, PartyPrivateCopy, PartyPrivateRaw, private_empty, private_full, private_which,
    },
    ty_eq::{EqualityProposition as EqProp, Witness, generics},
};

#[inline(always)]
const fn copy_ev<
    PrivateTo: GenericParty<PartySystem = P::PartySystem>,
    P: GenericParty,
    T: Copy,
>() -> Witness<
    impl EqProp<
        PartyPrivateRaw<bounds::Any, PrivateTo, P, T>,
        PartyPrivateRaw<bounds::Copy, PrivateTo, P, T>,
    >,
> {
    match const { private_which::<PrivateTo, P>() } {
        super::PrivateWhich::Full(e) => private_full::<bounds::Any, PrivateTo, P, T>(e)
            .sym()
            .and_then(private_full::<bounds::Copy, PrivateTo, P, T>(e))
            .join_left()
            .join(),
        super::PrivateWhich::Empty(e) => private_empty::<bounds::Any, PrivateTo, P, T>(e)
            .sym()
            .and_then(private_empty::<bounds::Copy, PrivateTo, P, T>(e))
            .join_right()
            .join(),
    }
}

impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<PartyPrivate<PrivateTo, P, T>> for PartyPrivateCopy<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: PartyPrivate<PrivateTo, P, T>) -> Self {
        Self(const { copy_ev::<PrivateTo, P, T>() }.cast(value.0))
    }
}
impl<PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<PartyPrivateCopy<PrivateTo, P, T>> for PartyPrivate<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: PartyPrivateCopy<PrivateTo, P, T>) -> Self {
        Self(const { copy_ev::<PrivateTo, P, T>().sym() }.cast(value.0))
    }
}

impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<&'a PartyPrivate<PrivateTo, P, T>> for &'a PartyPrivateCopy<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: &'a PartyPrivate<PrivateTo, P, T>) -> Self {
        TransparentWrapper::wrap_ref(
            const { copy_ev::<PrivateTo, P, T>().with_generic::<generics::Ref, _, _>() }
                .cast(&value.0),
        )
    }
}
impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<&'a PartyPrivateCopy<PrivateTo, P, T>> for &'a PartyPrivate<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: &'a PartyPrivateCopy<PrivateTo, P, T>) -> Self {
        TransparentWrapper::wrap_ref(
            const {
                copy_ev::<PrivateTo, P, T>()
                    .with_generic::<generics::Ref, _, _>()
                    .sym()
            }
            .cast(&value.0),
        )
    }
}
impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<&'a mut PartyPrivate<PrivateTo, P, T>> for &'a mut PartyPrivateCopy<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: &'a mut PartyPrivate<PrivateTo, P, T>) -> Self {
        TransparentWrapper::wrap_mut(
            const { copy_ev::<PrivateTo, P, T>().with_generic::<generics::RefMut, _, _>() }
                .cast(&mut value.0),
        )
    }
}
impl<'a, PrivateTo: GenericParty<PartySystem = P::PartySystem>, P: GenericParty, T: Copy>
    From<&'a mut PartyPrivateCopy<PrivateTo, P, T>> for &'a mut PartyPrivate<PrivateTo, P, T>
{
    #[inline(always)]
    fn from(value: &'a mut PartyPrivateCopy<PrivateTo, P, T>) -> Self {
        TransparentWrapper::wrap_mut(
            const {
                copy_ev::<PrivateTo, P, T>()
                    .with_generic::<generics::RefMut, _, _>()
                    .sym()
            }
            .cast(&mut value.0),
        )
    }
}

// TODO: we can do this for more containers.
