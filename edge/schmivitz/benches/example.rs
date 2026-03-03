use swanky_field_binary::F2;
use swanky_sieve_ir_api::{CircuitExecuter, CircuitResult, FieldBackend};

pub struct ExampleCircuit<const N: usize>;

impl<const N: usize> CircuitExecuter<F2> for ExampleCircuit<N> {
    fn execute<B: FieldBackend<F2>>(&self, backend: &mut B) -> CircuitResult<()> {
        let mut v = backend.input_private()?;

        // N additions
        for _ in 0..N {
            v = backend.add(&v, &v)?;
        }

        // N multiplications
        for _ in 0..N {
            v = backend.mul(&v, &v)?;
        }

        // backend.assert_zero(&v2)?;

        Ok(())
    }
}
