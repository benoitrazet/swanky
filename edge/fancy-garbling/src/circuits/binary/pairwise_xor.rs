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

pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;

    /// Circuit for testing [`PairwiseXor`].
    pub struct TestPairwiseXor(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestPairwiseXor {
        type Input = <PairwiseXor as Circuit<F>>::Input;
        type Output = <PairwiseXor as Circuit<F>>::Output;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            PairwiseXor.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestPairwiseXor {
        fn map(&self, inputs: Vec<<F as crate::Fancy>::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0 * 2);
            let (x, y) = inputs.split_at(self.0);
            (x.to_vec(), y.to_vec())
        }

        fn ninputs(&self) -> usize {
            self.0 * 2
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn pairwise_xor() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let n = 1 + (rng.r#gen::<usize>() % 200);
        let circuit = TestPairwiseXor(n);

        for _ in 0..100 {
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
            let output = Dummy::eval(&circuit, &(x, y)).unwrap();
            assert_eq!(output, expected);
        }
    }
}
