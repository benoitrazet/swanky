use crate::{GenericParty, either::PartyEither};

impl<P: GenericParty, A: Iterator, B: Iterator> Iterator for PartyEither<P, A, B> {
    type Item = PartyEither<P, A::Item, B::Item>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        match const { P::GENERIC_WHICH } {
            crate::GenericWhichParty::Party0(witness) => self
                .as_mut()
                .into_inner(witness)
                .next()
                .map(|x| PartyEither::new(witness, x)),
            crate::GenericWhichParty::Party1(witness) => self
                .as_mut()
                .into_inner(witness)
                .next()
                .map(|x| PartyEither::new(witness, x)),
        }
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match const { P::GENERIC_WHICH } {
            crate::GenericWhichParty::Party0(witness) => {
                self.as_ref().into_inner(witness).size_hint()
            }
            crate::GenericWhichParty::Party1(witness) => {
                self.as_ref().into_inner(witness).size_hint()
            }
        }
    }
}

impl<P: GenericParty, A: ExactSizeIterator, B: ExactSizeIterator> ExactSizeIterator
    for PartyEither<P, A, B>
{
}
