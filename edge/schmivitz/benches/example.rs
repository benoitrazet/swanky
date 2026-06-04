use fancy_garbling::{FancyBinary, FancyZeroKnowledge, circuit::Circuit};
use swanky_channel::Channel;
use swanky_error::Result;

pub struct ExampleCircuit<const N: usize>;

impl<F: FancyBinary + FancyZeroKnowledge, const N: usize> Circuit<F> for ExampleCircuit<N> {
    type Input = ();
    type Output = Vec<F::Item>; // TODO: Should be `()`.

    fn execute(
        &self,
        backend: &mut F,
        _: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut v = backend.receive(2, channel)?;

        // N additions
        for _ in 0..N {
            v = backend.xor(&v, &v);
        }

        // N multiplications
        for _ in 0..N {
            v = backend.and(&v, &v, channel)?;
        }

        // backend.assert_zero(&v2)?;

        Ok(vec![])
    }
}
