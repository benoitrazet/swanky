use core::marker::PhantomData;
use fancy_traits::{Circuit, FancyBinary};
use swanky_channel::Channel;
use swanky_error::Result;

/// Pairwise OR of two bitvectors.
#[derive(Default)]
pub struct PairwiseOr<'a>(PhantomData<&'a ()>);

impl<'a> PairwiseOr<'a> {
    /// Create a new [`PairwiseOr`] circuit.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<'a, F: FancyBinary> Circuit<F> for PairwiseOr<'a>
where
    F::Item: 'a,
{
    type Input = (&'a Vec<F::Item>, &'a Vec<F::Item>);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let (x, y) = inputs;
        x.iter()
            .zip(y.iter())
            .map(|(x, y)| backend.or(x, y, channel))
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use super::PairwiseOr;

    #[test]
    fn pairwise_or() {
        use fancy_plaintext::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let n = 1 + (rng.r#gen::<usize>() % 200);
            let x = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let y = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = x
                .iter()
                .zip(y.iter())
                .map(|(x, y)| DummyVal::new(x.val() | y.val(), 2))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&PairwiseOr::new(), (&x, &y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
