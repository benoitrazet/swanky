use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    Evaluator, FancyArithmetic, FancyBinary, FancyProj, Garbler, WireMod2, WireModQ,
    circuit::{Circuit, CircuitInputMapper},
    classic::GarbledCircuit,
    util::RngExt,
};
use std::{hint::black_box, time::Duration};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

fn bench_garble_binary_ex<Ex: CircuitInputMapper<Garbler<SwankyRng, WireMod2>>>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
) {
    c.bench_function(&format!("garbling::{name}_gb_ex (2)"), move |bench| {
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<WireMod2, _, _>(&ex, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_garble_arith_ex<Ex: CircuitInputMapper<Garbler<SwankyRng, WireModQ>>>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
    q: u16,
) {
    c.bench_function(&format!("garbling::{name}_gb_ex ({q})"), move |bench| {
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<WireModQ, _, _>(&ex, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_eval_binary_ex<
    Ex: CircuitInputMapper<Garbler<SwankyRng, WireMod2>> + CircuitInputMapper<Evaluator<WireMod2>>,
>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
) {
    c.bench_function(&format!("garbling::{name}_ev_ex (2)"), move |bench| {
        let mut rng = rand::thread_rng();
        let (encoder, gc, _) =
            GarbledCircuit::garble::<WireMod2, _, _>(&ex, SwankyRng::new()).unwrap();
        let inputs = (0..<Ex as CircuitInputMapper<Garbler<_, _>>>::ninputs(&ex))
            .map(|i| rng.gen_u16() % <Ex as CircuitInputMapper<Garbler<_, _>>>::modulus(&ex, i))
            .collect::<Vec<u16>>();
        let xs = encoder.encode_inputs(&inputs);
        bench.iter(|| {
            let ys = gc
                .eval_to_wirelabels(
                    &ex,
                    &<Ex as CircuitInputMapper<Evaluator<_>>>::map(&ex, xs.clone()),
                )
                .unwrap();
            black_box(ys);
        })
    });
}

fn bench_eval_arith_ex<
    Ex: CircuitInputMapper<Garbler<SwankyRng, WireModQ>> + CircuitInputMapper<Evaluator<WireModQ>>,
>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
    q: u16,
) {
    c.bench_function(&format!("garbling::{name}_ev_ex ({q})"), move |bench| {
        let mut rng = rand::thread_rng();
        let (encoder, gc, _) =
            GarbledCircuit::garble::<WireModQ, _, _>(&ex, SwankyRng::new()).unwrap();
        let inputs = (0..<Ex as CircuitInputMapper<Garbler<_, _>>>::ninputs(&ex))
            .map(|i| rng.gen_u16() % <Ex as CircuitInputMapper<Garbler<_, _>>>::modulus(&ex, i))
            .collect::<Vec<u16>>();
        let xs = encoder.encode_inputs(&inputs);
        bench.iter(|| {
            let ys = gc
                .eval_to_wirelabels(
                    &ex,
                    &<Ex as CircuitInputMapper<Evaluator<_>>>::map(&ex, xs.clone()),
                )
                .unwrap();
            black_box(ys);
        })
    });
}

const MIXED_OP_NUM_OPS: usize = 100_000;

struct MixedOp;
impl<F: FancyBinary> Circuit<F> for MixedOp {
    type Input = F::Item;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        input: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut x = input.clone();
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = backend.and(&x, &x, channel)?;
            } else {
                x = backend.xor(&x, &x);
            }
        }
        Ok(x)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for MixedOp {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 1);
        inputs[0].clone()
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

struct MixedOpArith(u16);
impl<F: FancyArithmetic> Circuit<F> for MixedOpArith {
    type Input = F::Item;
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        input: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut x = input.clone();
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = backend.mul(&x, &x, channel)?;
            } else {
                x = backend.add(&x, &x);
            }
        }
        Ok(x)
    }
}

impl<F: FancyArithmetic> CircuitInputMapper<F> for MixedOpArith {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 1);
        inputs[0].clone()
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        self.0
    }
}

struct Proj(u16, Vec<u16>);
impl<F: FancyProj> Circuit<F> for Proj {
    type Input = F::Item;
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        input: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        for _ in 0..1000 {
            let _ = backend.proj(input, self.0, Some(self.1.clone()), channel)?;
        }
        Ok(vec![])
    }
}

impl<F: FancyProj> CircuitInputMapper<F> for Proj {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 1);
        inputs[0].clone()
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        self.0
    }
}

struct Mul(u16);
impl<F: FancyArithmetic> Circuit<F> for Mul {
    type Input = F::Item;
    type Output = Vec<F::Item>;

    fn execute(
        &self,
        backend: &mut F,
        input: &Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        for _ in 0..1000 {
            let _ = backend.mul(input, input, channel)?;
        }
        Ok(vec![])
    }
}

impl<F: FancyArithmetic> CircuitInputMapper<F> for Mul {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 1);
        inputs[0].clone()
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        self.0
    }
}

fn proj_gb(c: &mut Criterion) {
    let tt = (0..2).map(|i| (i + 1) % 2).collect::<Vec<u16>>();
    bench_garble_arith_ex(c, "proj", Proj(2, tt), 2);
    let tt = (0..17).map(|i| (i + 1) % 17).collect::<Vec<u16>>();
    bench_garble_arith_ex(c, "proj", Proj(17, tt), 17);
}
fn proj_ev(c: &mut Criterion) {
    let tt = (0..2).map(|i| (i + 1) % 2).collect::<Vec<u16>>();
    bench_eval_arith_ex(c, "proj", Proj(2, tt), 2);
    let tt = (0..17).map(|i| (i + 1) % 17).collect::<Vec<u16>>();
    bench_eval_arith_ex(c, "proj", Proj(17, tt), 17);
}

fn mul_gb(c: &mut Criterion) {
    bench_garble_arith_ex(c, "mul", Mul(2), 2);
    bench_garble_arith_ex(c, "mul", Mul(17), 17)
}
fn mul_ev(c: &mut Criterion) {
    bench_eval_arith_ex(c, "mul", Mul(2), 2);
    bench_eval_arith_ex(c, "mul", Mul(17), 17)
}

fn mixed_op_gb(c: &mut Criterion) {
    bench_garble_binary_ex(c, "mixed_op", MixedOp);
    bench_garble_arith_ex(c, "mixed_op", MixedOpArith(17), 17);
}
fn mixed_op_ev(c: &mut Criterion) {
    bench_eval_binary_ex(c, "mixed_op", MixedOp);
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj_gb, proj_ev, mul_gb, mul_ev, mixed_op_gb, mixed_op_ev
}

criterion_main!(garbling);
