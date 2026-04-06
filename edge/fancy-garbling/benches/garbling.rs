use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    AllWire, Evaluator, FancyArithmetic, FancyProj, Garbler,
    circuit::{ArithmeticCircuit as Circuit, CircuitBuilder, CircuitExecutor, CircuitType},
    classic::GarbledCircuit,
    util::RngExt,
};
use std::{hint::black_box, time::Duration};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

fn bench_garble<F>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
where
    F: Fn(u16) -> Circuit + 'static,
{
    c.bench_function(&format!("garbling::{}_gb ({})", name, q), move |bench| {
        let circ = make_circuit(q);
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<AllWire, _, _>(&circ, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_garble_ex<Ex: CircuitExecutor<Garbler<SwankyRng, AllWire>>>(
    c: &mut Criterion,
    name: &str,
    ex: Ex,
    q: u16,
) {
    c.bench_function(&format!("Garbling::{name}_gb_ex ({q})"), move |bench| {
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<AllWire, _, _>(&ex, SwankyRng::new()).unwrap();
            black_box(gb);
        });
    });
}

fn bench_eval<F>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
where
    F: Fn(u16) -> Circuit + 'static,
{
    c.bench_function(&format!("garbling::{}_ev ({})", name, q), move |bench| {
        let mut rng = rand::thread_rng();
        let c = make_circuit(q);
        let (en, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&c, SwankyRng::new()).unwrap();
        let inps = (0..c.num_inputs())
            .map(|i| rng.gen_u16() % c.input_mod(i))
            .collect::<Vec<u16>>();
        let xs = en.encode_inputs(&inps);
        bench.iter(|| {
            let ys = ev.eval_to_wirelabels(&c, &xs).unwrap();
            black_box(ys);
        });
    });
}

fn bench_eval_ex<
    Ex1: CircuitExecutor<Garbler<SwankyRng, AllWire>>,
    Ex2: CircuitExecutor<Evaluator<AllWire>>,
>(
    c: &mut Criterion,
    name: &str,
    garbler: Ex1,
    evaluator: Ex2,
    q: u16,
) {
    c.bench_function(&format!("garbling::{name}_ev_ex ({q})"), move |bench| {
        let mut rng = rand::thread_rng();
        let (encoder, gc, _) =
            GarbledCircuit::garble::<AllWire, _, _>(&garbler, SwankyRng::new()).unwrap();
        let inputs = (0..garbler.ninputs())
            .map(|i| rng.gen_u16() % garbler.modulus(i))
            .collect::<Vec<u16>>();
        let xs = encoder.encode_inputs(&inputs);
        bench.iter(|| {
            let ys = gc.eval_to_wirelabels(&evaluator, &xs).unwrap();
            black_box(ys);
        })
    });
}

const MIXED_OP_NUM_OPS: usize = 100_000;

fn mixed_op_circuit(q: u16) -> Circuit {
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

struct MixedOp(u16);
impl<F: FancyArithmetic> CircuitExecutor<F> for MixedOp {
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

fn proj(q: u16) -> Circuit {
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

fn mul(q: u16) -> Circuit {
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
    bench_garble(c, "proj", proj, 2);
    bench_garble(c, "proj", proj, 17)
}
fn proj_ev(c: &mut Criterion) {
    bench_eval(c, "proj", proj, 2);
    bench_eval(c, "proj", proj, 17)
}

fn mul_gb(c: &mut Criterion) {
    bench_garble(c, "mul", mul, 2);
    bench_garble(c, "mul", mul, 17)
}
fn mul_ev(c: &mut Criterion) {
    bench_eval(c, "mul", mul, 2);
    bench_eval(c, "mul", mul, 17)
}

fn mixed_op_gb(c: &mut Criterion) {
    bench_garble(c, "mixed_op", mixed_op_circuit, 2);
    bench_garble_ex(c, "mixed_op", MixedOp(2), 2);
    bench_garble(c, "mixed_op", mixed_op_circuit, 17);
    bench_garble_ex(c, "mixed_op", MixedOp(17), 17);
}
fn mixed_op_ev(c: &mut Criterion) {
    bench_eval(c, "mixed_op", mixed_op_circuit, 2);
    bench_eval_ex(c, "mixed_op", MixedOp(2), MixedOp(2), 2);
    bench_eval(c, "mixed_op", mixed_op_circuit, 17);
    bench_eval_ex(c, "mixed_op", MixedOp(17), MixedOp(17), 17);
}

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj_gb, proj_ev, mul_gb, mul_ev, mixed_op_gb, mixed_op_ev
}

criterion_main!(garbling);
