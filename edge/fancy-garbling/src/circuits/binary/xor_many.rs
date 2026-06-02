use crate::{FancyBinary, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

/// Returns the XOR of a vector of items.
///
/// # Panics
/// Panics if no inputs are provided.
pub struct XorMany;

impl<F: FancyBinary> Circuit<F> for XorMany {
    type Input = Vec<F::Item>;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: &Self::Input,
        _: &mut Channel,
    ) -> Result<Self::Output> {
        assert!(!inputs.is_empty(), "`args` cannot be empty");
        Ok(inputs
            .iter()
            .skip(1)
            .fold(inputs[0].clone(), |acc, x| backend.xor(&acc, x)))
    }
}

#[cfg(test)]
pub mod test {
    use super::XorMany;

    #[test]
    fn xor_many() {
        use crate::dummy::{Dummy, DummyVal};
        use rand::Rng;

        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let n = 2 + (rng.r#gen::<usize>() % 200);
            let inputs = (0..n)
                .map(|_| DummyVal::rand_bool(&mut rng))
                .collect::<Vec<_>>();
            let expected = inputs.iter().fold(0, |acc, &x| x.val() ^ acc);
            let output = Dummy::eval(&XorMany, &inputs).unwrap();
            assert_eq!(output.val(), expected);
        }
    }
}
