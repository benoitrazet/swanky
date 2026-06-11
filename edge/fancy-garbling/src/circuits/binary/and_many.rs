use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns `true` if all inputs are `true`.
///
/// # Panics
/// Panics if no inputs are provided.
pub struct AndMany;

impl<F: FancyBinary> Circuit<F> for AndMany {
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
            .try_fold(inputs[0].clone(), |acc, x| backend.and(&acc, x, channel))
    }
}

#[cfg(test)]
pub mod test {
    use super::AndMany;

    #[test]
    fn and_many() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let n = 2 + (rng.r#gen::<usize>() % 200);
            let inputs = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(1, |acc, &x| x.val() & acc);
            let output = Dummy::eval(&AndMany, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}
