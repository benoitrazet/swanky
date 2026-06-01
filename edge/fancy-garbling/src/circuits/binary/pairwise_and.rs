use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Pairwise AND of two bitvectors.
pub struct PairwiseAnd;

impl<F: FancyBinary> Circuit<F> for PairwiseAnd {
    type Input = (Vec<F::Item>, Vec<F::Item>);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        inputs
            .0
            .iter()
            .zip(inputs.1.iter())
            .map(|(x, y)| backend.and(x, y, channel))
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use super::PairwiseAnd;

    #[test]
    fn pairwise_and() {
        use crate::dummy::{Dummy, DummyVal};
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
                .map(|(x, y)| DummyVal::new(x.val() & y.val(), 2))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&PairwiseAnd, &(x, y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
