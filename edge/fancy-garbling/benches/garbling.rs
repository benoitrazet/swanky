use criterion::{Criterion, criterion_group, criterion_main};
use fancy_garbling::{
    AllWire, FancyArithmetic,
    circuit::{ArithmeticCircuit as Circuit, CircuitBuilder, CircuitType},
    classic::GarbledCircuit,
    util::RngExt,
};
use std::time::Duration;
use swanky_aes_rng::AesRng;
use swanky_channel::Channel;

fn bench_garble<F>(c: &mut Criterion, name: &str, make_circuit: F, q: u16)
where
    F: Fn(u16) -> Circuit + 'static,
{
    c.bench_function(&format!("garbling::{}_gb ({})", name, q), move |bench| {
        let c = make_circuit(q);
        bench.iter(|| {
            let gb = GarbledCircuit::garble::<AllWire, _, _>(&c, AesRng::new()).unwrap();
            std::hint::black_box(gb);
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
        let (en, ev, _) = GarbledCircuit::garble::<AllWire, _, _>(&c, AesRng::new()).unwrap();
        let inps = (0..c.num_garbler_inputs())
            .map(|i| rng.gen_u16() % c.garbler_input_mod(i))
            .collect::<Vec<u16>>();
        let xs = en.encode_garbler_inputs(&inps);
        bench.iter(|| {
            let ys = ev.eval(&c, &xs, &[]).unwrap();
            std::hint::black_box(ys);
        });
    });
}

fn proj(q: u16) -> Circuit {
    Channel::with(std::io::empty(), |channel| {
        let tt = (0..q).map(|i| (i + 1) % q).collect::<Vec<u16>>();
        let mut b = CircuitBuilder::new();
        let x = b.garbler_input(q);
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
        let x = b.garbler_input(q);
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

criterion_group! {
    name = garbling;
    config = Criterion::default().warm_up_time(Duration::from_millis(100));
    targets = proj_gb, proj_ev, mul_gb, mul_ev
}

criterion_main!(garbling);
