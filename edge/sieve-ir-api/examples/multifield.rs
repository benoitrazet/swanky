use swanky_field_binary::F2;
use swanky_field_ff_primes::F128p;
use swanky_sieve_ir_api::*;

fn sieve_compiled_f<B>(
    backend: &mut B,
    arg1: &B::Wire,
    arg2: &B::Wire,
    arg3: &B::Wire,
) -> CircuitResult<(B::Wire, B::Wire)>
where
    B: FieldBackend<F2>,
{
    let v1 = backend.add(arg1, arg2)?;
    let v2 = backend.add(arg3, &v1)?;

    Ok((v1, v2))
}

#[allow(dead_code)]
fn example1<B>(backend: &mut B) -> CircuitResult<()>
where
    B: FieldBackend<F2>,
    B: FieldBackend<F128p>,
{
    let v0 = <B as FieldBackend<F2>>::input_private(backend)?;
    let v1 = <B as FieldBackend<F2>>::mul(backend, &v0, &v0)?;
    let v2 = <B as FieldBackend<F2>>::add(backend, &v1, &v1)?;

    <B as FieldBackend<F2>>::assert_zero(backend, &v2)?;

    let p0 = <B as FieldBackend<F128p>>::input_private(backend)?;
    let p1 = <B as FieldBackend<F128p>>::input_private(backend)?;
    let p2 = <B as FieldBackend<F128p>>::add(backend, &p0, &p1)?;
    <B as FieldBackend<F128p>>::assert_zero(backend, &p2)?;

    let (v3, v4) = sieve_compiled_f(backend, &v0, &v1, &v2)?;
    <B as FieldBackend<F2>>::assert_zero(backend, &v3)?;
    <B as FieldBackend<F2>>::assert_zero(backend, &v4)?;

    Ok(())
}

fn main() {
    println!("This module demonstrates a simple ZK circuit in Rust.");
}
