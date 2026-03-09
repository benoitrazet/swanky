use bytemuck::{TransparentWrapper, Zeroable};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use swanky_field::{FiniteField, FiniteRing, IsSubFieldOf};
use swanky_field_binary::{F2, SmallBinaryField};
use swanky_party::either::PartyEitherCopy;
use swanky_party::private::PartyPrivateCopy;
use swanky_party::ty_eq::{EqualityProposition, Witness};

use crate::party;
use crate::party::{Party, Prover, Verifier, WhichParty};
use crate::specialization::{FiniteFieldSpecialization, SmallBinaryFieldSpecialization};

pub type MacConstantContext<P, FE> = PartyEitherCopy<P, (), FE>;

pub trait MacTypes: 'static + Sized + Clone + Copy + Send + Sync {
    type VF: FiniteField + IsSubFieldOf<Self::TF>;
    type TF: FiniteField;
    type S: FiniteFieldSpecialization<Self::VF, Self::TF>;
}
impl<VF: FiniteField + IsSubFieldOf<TF>, TF: FiniteField, S: FiniteFieldSpecialization<VF, TF>>
    MacTypes for (VF, TF, S)
{
    type VF = VF;
    type TF = TF;
    type S = S;
}

// See https://github.com/rust-lang/rust/issues/104918
#[allow(type_alias_bounds)]
pub type SenderPairContents<T: MacTypes> =
    <<T as MacTypes>::S as FiniteFieldSpecialization<T::VF, T::TF>>::SenderPairContents;

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Mac<P: Party, T: MacTypes> {
    contents: PartyEitherCopy<P, SenderPairContents<T>, T::TF>,
}
unsafe impl<P: Party, T: MacTypes>
    TransparentWrapper<PartyEitherCopy<P, SenderPairContents<T>, T::TF>> for Mac<P, T>
{
}
impl<P: Party, T: MacTypes> Mac<P, T> {
    pub fn cast_slice<P2: Party>(
        _e: Witness<impl EqualityProposition<P, P2>>,
        macs: &[Self],
    ) -> &[Mac<P2, T>] {
        unsafe { std::slice::from_raw_parts(macs.as_ptr() as *const _, macs.len()) }
    }
    pub fn cast_slice_mut<P2: Party>(
        _e: Witness<impl EqualityProposition<P, P2>>,
        macs: &mut [Self],
    ) -> &mut [Mac<P2, T>] {
        unsafe { std::slice::from_raw_parts_mut(macs.as_mut_ptr() as *mut _, macs.len()) }
    }
    pub fn zero() -> Self {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    PartyEitherCopy::new(e, T::S::new_sender_pair(T::VF::ZERO, T::TF::ZERO))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::new(e, T::TF::ZERO),
            },
        }
    }
    pub fn constant(ctx: &MacConstantContext<P, T::TF>, value: T::VF) -> Self {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    PartyEitherCopy::new(e, T::S::new_sender_pair(value, T::TF::ZERO))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::new(e, value * ctx.into_inner(e)),
            },
        }
    }
    pub fn prover_new(
        e: Witness<impl EqualityProposition<P, Prover>>,
        x: T::VF,
        beta: T::TF,
    ) -> Self {
        Mac {
            contents: PartyEitherCopy::new(e, T::S::new_sender_pair(x, beta)),
        }
    }
    pub fn verifier_new(e: Witness<impl EqualityProposition<P, Verifier>>, tag: T::TF) -> Self {
        Mac {
            contents: PartyEitherCopy::new(e, tag),
        }
    }
    pub fn prover_extract(
        &self,
        e: Witness<impl EqualityProposition<P, Prover>>,
    ) -> (T::VF, T::TF) {
        T::S::extract_sender_pair(self.contents.into_inner(e))
    }
    pub fn tag(&self, e: Witness<impl EqualityProposition<P, Verifier>>) -> T::TF {
        self.contents.into_inner(e)
    }
    pub fn mac_value(&self) -> PartyPrivateCopy<Prover, P, T::VF> {
        match P::WHICH {
            WhichParty::Prover(e) => PartyPrivateCopy::new(self.prover_extract(e).0),
            WhichParty::Verifier(e) => PartyPrivateCopy::empty(e),
        }
    }
    pub fn beta(&self) -> PartyPrivateCopy<Prover, P, T::TF> {
        match P::WHICH {
            WhichParty::Prover(e) => PartyPrivateCopy::new(self.prover_extract(e).1),
            WhichParty::Verifier(e) => PartyPrivateCopy::empty(e),
        }
    }
}
impl<P: Party, T: MacTypes> Mul<T::VF> for Mac<P, T> {
    type Output = Self;

    fn mul(self, rhs: T::VF) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    PartyEitherCopy::new(e, T::S::new_sender_pair(x * rhs, rhs * beta))
                }
                WhichParty::Verifier(e) => {
                    PartyEitherCopy::new(e, rhs * self.contents.into_inner(e))
                }
            },
        }
    }
}
impl<P: Party, T: MacTypes> MulAssign<T::VF> for Mac<P, T> {
    fn mul_assign(&mut self, rhs: T::VF) {
        *self = *self * rhs;
    }
}
impl<P: Party, T: MacTypes> Add<Mac<P, T>> for Mac<P, T> {
    type Output = Self;

    fn add(self, rhs: Mac<P, T>) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    let (x2, beta2) = rhs.prover_extract(e);
                    PartyEitherCopy::new(e, T::S::new_sender_pair(x + x2, beta + beta2))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::new(
                    e,
                    self.contents.into_inner(e) + rhs.contents.into_inner(e),
                ),
            },
        }
    }
}
impl<P: Party, T: MacTypes> AddAssign<Mac<P, T>> for Mac<P, T> {
    fn add_assign(&mut self, rhs: Mac<P, T>) {
        *self = *self + rhs;
    }
}
impl<P: Party, T: MacTypes> Sub<Mac<P, T>> for Mac<P, T> {
    type Output = Self;

    fn sub(self, rhs: Mac<P, T>) -> Self::Output {
        Mac {
            contents: match P::WHICH {
                WhichParty::Prover(e) => {
                    let (x, beta) = self.prover_extract(e);
                    let (x2, beta2) = rhs.prover_extract(e);
                    PartyEitherCopy::new(e, T::S::new_sender_pair(x - x2, beta - beta2))
                }
                WhichParty::Verifier(e) => PartyEitherCopy::new(
                    e,
                    self.contents.into_inner(e) - rhs.contents.into_inner(e),
                ),
            },
        }
    }
}
impl<P: Party, T: MacTypes> SubAssign<Mac<P, T>> for Mac<P, T> {
    fn sub_assign(&mut self, rhs: Mac<P, T>) {
        *self = *self - rhs;
    }
}
impl<P: Party, T: MacTypes> Default for Mac<P, T> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<T: MacTypes> From<(T::VF, T::TF)> for Mac<party::Prover, T> {
    fn from(value: (T::VF, T::TF)) -> Self {
        Mac::prover_new(Witness::EQUAL_TYPES, value.0, value.1)
    }
}
impl<T: MacTypes> Into<(T::VF, T::TF)> for Mac<party::Prover, T> {
    fn into(self) -> (T::VF, T::TF) {
        self.prover_extract(Witness::EQUAL_TYPES)
    }
}
impl<P: Party, T: MacTypes> std::fmt::Debug for Mac<P, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let (x, beta) = self.prover_extract(e);
                write!(
                    f,
                    "Mac<Prover, {}> {{ x: {x:?}, beta: {beta:?} }}",
                    std::any::type_name::<T>()
                )
            }
            WhichParty::Verifier(e) => write!(
                f,
                "Mac<Verifier, {}> {{ tag: {:?} }}",
                std::any::type_name::<T>(),
                self.tag(e)
            ),
        }
    }
}

unsafe impl<P: Party, TF: SmallBinaryField> Zeroable
    for Mac<P, (F2, TF, SmallBinaryFieldSpecialization)>
where
    F2: IsSubFieldOf<TF>,
{
}
