use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Pairwise XOR of two bitvectors.
pub struct PairwiseXor;

impl<F: FancyBinary> Circuit<F> for PairwiseXor {
    type Input = (Vec<F::Item>, Vec<F::Item>);
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        Ok(inputs
            .0
            .iter()
            .zip(inputs.1.iter())
            .map(|(x, y)| backend.xor(x, y))
            .collect())
    }
}

#[cfg(test)]
pub mod test {
    use super::PairwiseXor;

    #[test]
    fn pairwise_xor() {
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
                .map(|(x, y)| DummyVal::new(x.val() ^ y.val(), 2))
                .collect::<Vec<_>>();
            let output = Dummy::eval(&PairwiseXor, &(x, y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
