use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns `true` if any input is `true`.
///
/// # Panics
/// Panics if no inputs are provided.
pub struct OrMany;

impl<F: FancyBinary> Circuit<F> for OrMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`args` cannot be empty");
        inputs
            .iter()
            .skip(1)
            .try_fold(inputs[0].clone(), |acc, x| backend.or(&acc, x, channel))
    }
}

pub mod test {
    use super::*;
    use crate::circuit::CircuitExecutor;

    /// Circuit for testing [`OrMany`].
    pub struct TestOrMany(pub usize);
    impl<F: FancyBinary> Circuit<F> for TestOrMany {
        type Input = Vec<F::Item>;
        type Output = F::Item;

        fn execute(
            &self,
            backend: &mut F,
            inputs: &Self::Input,
            channel: &mut Channel,
        ) -> Result<Self::Output> {
            OrMany.execute(backend, inputs, channel)
        }
    }

    impl<F: FancyBinary> CircuitExecutor<F> for TestOrMany {
        fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
            assert_eq!(inputs.len(), self.0);
            inputs
        }

        fn ninputs(&self) -> usize {
            self.0
        }

        fn modulus(&self, _: usize) -> u16 {
            2
        }
    }

    #[test]
    fn or_many() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let n = 2 + (rng.r#gen::<usize>() % 200);
        let c = TestOrMany(n);

        for _ in 0..16 {
            let inputs = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x.val() | acc);
            let output = Dummy::eval(&c, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}
