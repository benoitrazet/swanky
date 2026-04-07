use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    AllWire, Evaluator, FancyArithmetic, FancyBinary, FancyProj, Garbler, WireMod2, WireModQ,
    circuit::{ArithmeticCircuit, BinaryCircuit, CircuitBuilder, CircuitExecutor},
    classic::GarbledCircuit,
    util::RngExt,
};
use std::{hint::black_box, time::Duration};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

fn bench_garble_binary<F>(c: &mut Criterion, name: &str, f: F)
where
    F: Fn() -> BinaryCircuit + 'static,
{
    c.bench_function(&format!("garbling::{name}_gb (2)"), move |bench| {
        let circ = f();
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_garble_arith<F>(c: &mut Criterion, name: &str, f: F, q: u16)
where
    F: Fn(u16) -> ArithmeticCircuit + 'static,
{
    c.bench_function(&format!("garbling::{name}_gb ({q})"), move |bench| {
        let circ = f(q);
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<WireModQ, _, _>(&circ, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_garble_binary_ex<Ex: CircuitExecutor<Garbler<SwankyRng, WireMod2>>>(
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

fn bench_garble_arith_ex<Ex: CircuitExecutor<Garbler<SwankyRng, WireModQ>>>(
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

fn bench_eval_binary<F>(c: &mut Criterion, name: &str, f: F)
where
    F: Fn() -> BinaryCircuit + 'static,
{
    c.bench_function(&format!("garbling::{name}_ev (2)"), move |bench| {
        let mut rng = rand::thread_rng();
        let circ = f();
        let (en, ev, _) =
            GarbledCircuit::garble::<WireMod2, _, _>(&circ, SwankyRng::new()).unwrap();
        let inps =
            (0..<BinaryCircuit as CircuitExecutor<Garbler<SwankyRng, WireMod2>>>::ninputs(&circ))
                .map(|i| {
                    rng.gen_u16()
                        % <BinaryCircuit as CircuitExecutor<Garbler<SwankyRng, WireMod2>>>::modulus(
                            &circ, i,
                        )
                        % 2
                })
                .collect::<Vec<u16>>();
        let xs = en.encode_inputs(&inps);
        bench.iter(|| {
            let ys = ev.eval_to_wirelabels(&circ, &xs).unwrap();
            black_box(ys);
        });
    });
}

fn bench_eval_arith<F>(c: &mut Criterion, name: &str, f: F, q: u16)
where
    F: Fn(u16) -> ArithmeticCircuit + 'static,
{
    c.bench_function(&format!("garbling::{name}_ev ({q})"), move |bench| {
        let mut rng = rand::thread_rng();
        let circ = f(q);
        let (en, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
        let inps = (0
            ..<ArithmeticCircuit as CircuitExecutor<Garbler<SwankyRng, AllWire>>>::ninputs(&circ))
            .map(|i| {
                rng.gen_u16()
                    % <ArithmeticCircuit as CircuitExecutor<Garbler<SwankyRng, AllWire>>>::modulus(
                        &circ, i,
                    )
                    % q
            })
            .collect::<Vec<u16>>();
        let xs = en.encode_inputs(&inps);
        bench.iter(|| {
            let ys = ev.eval_to_wirelabels(&circ, &xs).unwrap();
            black_box(ys);
        });
    });
}

fn bench_eval_binary_ex<
    Ex: CircuitExecutor<Garbler<SwankyRng, WireMod2>> + CircuitExecutor<Evaluator<WireMod2>>,
>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
) {
    c.bench_function(&format!("garbling::{name}_ev_ex (2)"), move |bench| {
        let mut rng = rand::thread_rng();
        let (encoder, gc, _) =
            GarbledCircuit::garble::<WireMod2, _, _>(&ex, SwankyRng::new()).unwrap();
        let inputs = (0..<Ex as CircuitExecutor<Garbler<_, _>>>::ninputs(&ex))
            .map(|i| rng.gen_u16() % <Ex as CircuitExecutor<Garbler<_, _>>>::modulus(&ex, i))
            .collect::<Vec<u16>>();
        let xs = encoder.encode_inputs(&inputs);
        bench.iter(|| {
            let ys = gc.eval_to_wirelabels(&ex, &xs).unwrap();
            black_box(ys);
        })
    });
}

const MIXED_OP_NUM_OPS: usize = 100_000;

fn mixed_op_circuit_binary() -> BinaryCircuit {
    Channel::with(std::io::empty(), |channel| {
        let mut b = CircuitBuilder::new();
        let mut x = b.input(2);
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = b.and(&x, &x, channel)?;
            } else {
                x = b.xor(&x, &x);
            }
        }
        Ok(b.finish())
    })
    .unwrap()
}

fn mixed_op_circuit_arith(q: u16) -> ArithmeticCircuit {
    Channel::with(std::io::empty(), |channel| {
        let mut b = CircuitBuilder::new();
        let mut x = b.input(q);
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = b.mul(&x, &x, channel)?;
            } else {
                x = b.add(&x, &x);
            }
        }
        Ok(b.finish())
    })
    .unwrap()
}

struct MixedOp;
impl<F: FancyBinary> CircuitExecutor<F> for MixedOp {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> Result<Vec<F::Item>> {
        let mut x = inputs[0].clone();
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = backend.and(&x, &x, channel)?;
            } else {
                x = backend.xor(&x, &x);
            }
        }
        Ok(vec![x])
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

struct MixedOpArith(u16);
impl<F: FancyArithmetic> CircuitExecutor<F> for MixedOpArith {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> Result<Vec<F::Item>> {
        let mut x = inputs[0].clone();
        for step in 0..MIXED_OP_NUM_OPS {
            if step % 2 == 1 {
                x = backend.mul(&x, &x, channel)?;
            } else {
                x = backend.add(&x, &x);
            }
        }
        Ok(vec![x])
    }

    fn ninputs(&self) -> usize {
        1
    }

    fn modulus(&self, _: usize) -> u16 {
        self.0
    }
}

fn proj(q: u16) -> ArithmeticCircuit {
    Channel::with(std::io::empty(), |channel| {
        let tt = (0..q).map(|i| (i + 1) % q).collect::<Vec<u16>>();
        let mut b = CircuitBuilder::new();
        let x = b.input(q);
        for _ in 0..1000 {
            let _ = b.proj(&x, q, Some(tt.clone()), channel).unwrap();
        }
        Ok(b.finish())
    })
    .unwrap()
}

fn mul(q: u16) -> ArithmeticCircuit {
    Channel::with(std::io::empty(), |channel| {
        let mut b = CircuitBuilder::new();
        let x = b.input(q);
        for _ in 0..1000 {
            let _ = b.mul(&x, &x, channel).unwrap();
        }
        Ok(b.finish())
    })
    .unwrap()
}

fn proj_gb(c: &mut Criterion) {
    bench_garble_arith(c, "proj", proj, 2);
    bench_garble_arith(c, "proj", proj, 17)
}
fn proj_ev(c: &mut Criterion) {
    bench_eval_arith(c, "proj", proj, 2);
    bench_eval_arith(c, "proj", proj, 17)
}

fn mul_gb(c: &mut Criterion) {
    bench_garble_arith(c, "mul", mul, 2);
    bench_garble_arith(c, "mul", mul, 17)
}
fn mul_ev(c: &mut Criterion) {
    bench_eval_arith(c, "mul", mul, 2);
    bench_eval_arith(c, "mul", mul, 17)
}

fn mixed_op_gb(c: &mut Criterion) {
    bench_garble_binary(c, "mixed_op", mixed_op_circuit_binary);
    bench_garble_binary_ex(c, "mixed_op", MixedOp);
    bench_garble_arith(c, "mixed_op", mixed_op_circuit_arith, 17);
    bench_garble_arith_ex(c, "mixed_op", MixedOpArith(17), 17);
}
fn mixed_op_ev(c: &mut Criterion) {
    bench_eval_binary(c, "mixed_op", mixed_op_circuit_binary);
    bench_eval_binary_ex(c, "mixed_op", MixedOp);
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj_gb, proj_ev, mul_gb, mul_ev, mixed_op_gb, mixed_op_ev
}

criterion_main!(garbling);
