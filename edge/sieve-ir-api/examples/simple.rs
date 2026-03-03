use swanky_field_binary::F2;
use swanky_sieve_ir_api::*;

fn example1<B>(backend: &mut B) -> CircuitResult<()>
where
    B: FieldBackend<F2>,
{
    let v0 = backend.input_private()?;
    let v1 = backend.mul(&v0, &v0)?;
    let v2 = backend.add(&v1, &v1)?;

    backend.assert_zero(&v2)?;

    Ok(())
}

fn main() {
    println!("This module demonstrates a simple ZK circuit in Rust.");
}
