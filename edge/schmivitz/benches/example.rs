use fancy_traits::{Circuit, FancyBinary, FancyZeroKnowledge};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_sieve_ir_api::{
    CircuitExecuter, CircuitResult, FieldBackend, HigherDegreeBackend, HigherDegreeCircuitExecuter,
};

pub struct ExampleCircuit<const N: usize>;

impl<F: FancyBinary + FancyZeroKnowledge, const N: usize> Circuit<F> for ExampleCircuit<N> {
    type Input = ();
    type Output = Vec<F::Item>; // TODO: Should be `()`.

    fn execute(
        &self,
        backend: &mut F,
        _: Self::Input,
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

// This circuit has no higher degree constraints, so executing it on a `HigherDegreeBackend` only
// exercises the `FieldBackend` gates.
impl<const N: usize> HigherDegreeCircuitExecuter<F2, F128b> for ExampleCircuit<N> {
    fn execute<B: HigherDegreeBackend<F2, F128b>>(&self, backend: &mut B) -> CircuitResult<()> {
        <Self as CircuitExecuter<F2>>::execute(self, backend)
    }
}

impl<const N: usize> CircuitExecuter<F2> for ExampleCircuit<N> {
    fn execute<B: FieldBackend<F2>>(&self, backend: &mut B) -> CircuitResult<()> {
        let mut v = backend.input_private()?;

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
