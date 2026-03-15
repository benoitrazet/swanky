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

#[cfg(test)]
mod tests {
    use crate::ty_eq::Witness;

    use super::*;

    party_system! {
        mod ps {
            PartyA,
            PartyB,
        }
    }
    use ps::{PartyA, PartyB};

    #[test]
    fn iter_next() {
        let iter_a: std::iter::Once<_> = std::iter::once(1);
        let iter_b: std::iter::Once<_> = std::iter::once("a");

        let mut pe_a: PartyEither<PartyA, std::iter::Once<_>, std::iter::Once<_>> =
            PartyEither::new(Witness::EQUAL_TYPES, iter_a);
        let mut pe_b: PartyEither<PartyB, std::iter::Once<_>, std::iter::Once<_>> =
            PartyEither::new(Witness::EQUAL_TYPES, iter_b);

        assert_eq!(
            pe_a.next(),
            Some(PartyEither::<PartyA, i32, &str>::new(
                Witness::EQUAL_TYPES,
                1
            ))
        );

        assert_eq!(
            pe_b.next(),
            Some(PartyEither::<PartyB, i32, &str>::new(
                Witness::EQUAL_TYPES,
                "a"
            ))
        );
    }

    #[test]
    fn iter_size_hint() {
        let iter_a = std::iter::once(1);
        let iter_b = std::iter::once("a");

        let pe_a: PartyEither<PartyA, std::iter::Once<_>, std::iter::Once<&str>> =
            PartyEither::new(Witness::EQUAL_TYPES, iter_a);
        let pe_b: PartyEither<PartyB, std::iter::Once<i32>, std::iter::Once<_>> =
            PartyEither::new(Witness::EQUAL_TYPES, iter_b);

        assert_eq!(pe_a.size_hint(), (1, Some(1)));
        assert_eq!(pe_b.size_hint(), (1, Some(1)));
    }
}
