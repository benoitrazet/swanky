use std::{hint::black_box, time::Instant};

use fancy_garbling::{
    Circuit, CircuitInputMapper, Evaluator as SemiHonestEvaluator, FancyBinary, FancyEncode,
    FancyOutput, Flatten, Garbler as SemiHonestGarbler, WireMod2,
    circuit_analyzer::CircuitAnalyzer, circuits::LinearOram, classic::GarbledCircuit,
};
use swanky_authenticated_garbling::{
    Evaluator, Garbler, WirePreProcessor,
    ps::{PartyEvaluator, PartyGarbler},
};
use swanky_channel::Channel;
use swanky_error::Result;
use swanky_rng::SwankyRng;

struct And(usize);
impl<F: FancyBinary> Circuit<F> for And {
    type Input = (F::Item, F::Item);
    type Output = F::Item;

    fn execute(
        &self,
        backend: &mut F,
        inputs: Self::Input,
        channel: &mut Channel,
    ) -> Result<Self::Output> {
        let mut z = backend.and(&inputs.0, &inputs.1, channel)?;
        for _ in 0..self.0 {
            z = backend.and(&z, &inputs.1, channel)?;
        }
        Ok(z)
    }
}

impl<F: FancyBinary> CircuitInputMapper<F> for And {
    fn map(&self, inputs: Vec<F::Item>) -> Self::Input {
        assert_eq!(inputs.len(), 2);
        (inputs[0].clone(), inputs[1].clone())
    }

    fn ninputs(&self) -> usize {
        2
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

fn stats<C>(name: &str, circuit: &C) -> Result<()>
where
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<SemiHonestGarbler<SwankyRng, WireMod2>>
        + CircuitInputMapper<SemiHonestEvaluator<WireMod2>>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<Garbler<SwankyRng>>
        + CircuitInputMapper<Evaluator>
        + Sync,
{
    let mut analyzer = CircuitAnalyzer::new();
    analyzer.eval(circuit)?;
    let nands = analyzer.nands();

    let inputs = (0..<C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit))
        .map(|_| 0)
        .collect::<Vec<u16>>();
    let moduli = (0..<C as CircuitInputMapper<CircuitAnalyzer>>::ninputs(circuit))
        .map(|_| 2)
        .collect::<Vec<u16>>();

    println!("*");
    println!("* Circuit: {name} | # ANDs: {nands}");
    println!("*");

    println!("=== Classic Garbling ===");
    let t = Instant::now();
    let (encoder, gc, _) = GarbledCircuit::garble::<WireMod2, _, _>(circuit, SwankyRng::new())?;
    let time = t.elapsed();
    println!("Garbler: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    let xs = encoder.encode_inputs(&inputs);
    let t = Instant::now();
    let ys = gc.eval_to_wirelabels(
        circuit,
        <C as CircuitInputMapper<SemiHonestEvaluator<_>>>::map(circuit, xs.clone()),
    )?;
    black_box(ys);
    let time = t.elapsed();
    println!("Evaluator: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    println!("=== Streaming Garbling ===");

    let ((mut gb, zeros), (mut ev, wires)) = swanky_channel::local::local_channel_pair(
        |channel| {
            let mut gb = SemiHonestGarbler::<_, WireMod2>::new(SwankyRng::new(), channel)?;
            let zeros = gb.encode_many(&inputs, &moduli, channel)?;
            Ok((gb, zeros))
        },
        |channel| {
            let mut ev = SemiHonestEvaluator::<WireMod2>::new(channel)?;
            let wires = ev.receive_many(&moduli, channel)?;
            Ok((ev, wires))
        },
    )?;

    let t = Instant::now();
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let outputs = circuit.execute(
                &mut gb,
                <C as CircuitInputMapper<SemiHonestGarbler<_, _>>>::map(circuit, zeros),
                channel,
            )?;
            gb.outputs(&outputs.flatten(), channel)?;
            Ok(())
        },
        |channel| {
            let outputs = circuit.execute(
                &mut ev,
                <C as CircuitInputMapper<SemiHonestEvaluator<_>>>::map(circuit, wires),
                channel,
            )?;
            Ok(ev.outputs(&outputs.flatten(), channel)?.unwrap())
        },
    )?;
    black_box(result);
    let time = t.elapsed();
    println!("Garbler: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    println!("=== Authenticated Garbling ===");
    let ((mut gb, inputs_gb), (mut ev, inputs_ev)) = swanky_channel::local::local_channel_pair(
        |channel: &mut Channel<'_>| {
            let mut gb = Garbler::new(circuit, channel, SwankyRng::new())?;
            let inputs = gb.encode_many(&inputs, &moduli, channel)?;
            Ok((gb, inputs))
        },
        |channel| {
            let mut ev = Evaluator::new(circuit, channel, &mut SwankyRng::new())?;
            let inputs = ev.receive_many(&moduli, channel)?;
            Ok((ev, inputs))
        },
    )?;

    let t = Instant::now();
    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let outputs = circuit.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<_>>>::map(circuit, inputs_gb),
                channel,
            )?;
            gb.outputs(&outputs.flatten(), channel)
        },
        |channel| {
            let outputs = circuit.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator>>::map(circuit, inputs_ev),
                channel,
            )?;
            ev.outputs(&outputs.flatten(), channel)
        },
    )?;
    black_box(result);
    let time = t.elapsed();
    println!("Total: {:?}", time);
    println!(
        "Gates per second: {:?}",
        (nands as u128) / time.as_millis() * 1000
    );

    Ok(())
}

fn main() -> Result<()> {
    stats("AND", &And(1_000_000))?;
    stats("Linear ORAM", &LinearOram::<1024>::new(1024))?;
    Ok(())
}
