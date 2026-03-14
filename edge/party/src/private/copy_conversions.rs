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

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    #[test]
    fn copy_ev_exhaustive() {
        let w = copy_ev::<PartyA, PartyA, _>();
        let pp: PartyPrivate<PartyA, PartyA, _> = PartyPrivate::default();
        let pp_copy: PartyPrivateCopy<PartyA, PartyA, _> = PartyPrivateCopy(w.cast(pp.0));
        assert_eq!(pp.0, pp_copy.0);

        let pp: PartyPrivate<PartyB, PartyB, _> = PartyPrivate::new_with(|| 17);
        let pp_copy: PartyPrivateCopy<PartyB, PartyB, _> = PartyPrivateCopy(w.cast(pp.0));
        assert_eq!(pp.0, pp_copy.0);

        let w = copy_ev::<PartyB, PartyA, i32>();
        let pp: PartyPrivate<PartyB, PartyA, _> = PartyPrivate::new(17);
        let pp_copy: PartyPrivateCopy<PartyB, PartyA, i32> = PartyPrivateCopy(w.cast(pp.0));
        assert_eq!(pp.0, pp_copy.0);

        let pp: PartyPrivate<PartyA, PartyB, _> = PartyPrivate::new_with(|| 17);
        let pp_copy: PartyPrivateCopy<PartyA, PartyB, i32> = PartyPrivateCopy(w.cast(pp.0));
        assert_eq!(pp.0, pp_copy.0);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn private_to_private_copy() {
        let pp: PartyPrivate<PartyA, PartyA, _> = PartyPrivate::new(17);
        let pp_copy = PartyPrivateCopy::from(pp.clone());
        assert_eq!(
            pp.unwrap_or_else(|| unreachable!()),
            pp_copy.clone().unwrap_or_else(|| unreachable!())
        );
    }

    #[test]
    fn private_to_private_copy_refs() {
        let pp_ref: &PartyPrivate<PartyA, PartyA, _> = &PartyPrivate::new(17);
        let pp_copy_ref = <&PartyPrivateCopy<_, _, _>>::from(pp_ref);
        assert_eq!(
            pp_ref.clone().unwrap_or_else(|| unreachable!()),
            pp_copy_ref.unwrap_or_else(|| unreachable!())
        );
    }

    #[test]
    fn private_to_private_copy_mut_refs() {
        let pp_mut_ref: &mut PartyPrivate<PartyA, PartyA, _> = &mut PartyPrivate::new(17);
        let pp_copy_mut_ref = <&mut PartyPrivateCopy<_, _, _>>::from(pp_mut_ref);
        assert_eq!(pp_copy_mut_ref.unwrap_or_else(|| unreachable!()), 17);
    }

    #[test]
    fn private_copy_to_private() {
        let pp_copy: PartyPrivateCopy<PartyA, PartyB, _> = PartyPrivateCopy::default();
        let pp = PartyPrivate::from(pp_copy);
        assert_eq!(pp_copy.unwrap_or_else(|| 17), pp.unwrap_or_else(|| 17),);
    }

    #[test]
    fn private_copy_to_private_refs() {
        let pp_copy_ref: &PartyPrivateCopy<PartyA, PartyB, _> = &PartyPrivateCopy::default();
        let pp_ref = <&PartyPrivate<_, _, _>>::from(pp_copy_ref);
        assert_eq!(
            pp_copy_ref.unwrap_or_else(|| 17),
            pp_ref.clone().unwrap_or_else(|| 17)
        );
    }

    #[test]
    fn private_copy_to_private_mut_refs() {
        let pp_copy_mut_ref: &mut PartyPrivateCopy<PartyA, PartyB, _> =
            &mut PartyPrivateCopy::default();
        let pp_mut_ref = <&mut PartyPrivate<_, _, _>>::from(pp_copy_mut_ref);
        assert_eq!(pp_mut_ref.clone().unwrap_or_else(|| 17), 17);
    }
}
