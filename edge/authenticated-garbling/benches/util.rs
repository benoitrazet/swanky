use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_plaintext::Dummy;
use fancy_traits::{CircuitInputMapper, FancyEncode, FancyOutput, Flatten};
use swanky_authenticated_garbling::{
    Evaluator, Garbler, WirePreProcessor,
    ps::{PartyEvaluator, PartyGarbler},
};
use swanky_rng::SwankyRng;

/// Circuit Runner
pub fn test_circuit<
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<Garbler<SwankyRng>>
        + CircuitInputMapper<Evaluator>
        + CircuitInputMapper<Dummy>
        + Sync,
>(
    inputs_gb: &[u16],
    inputs_ev: &[u16],
    rng_gb: SwankyRng,
    rng_ev: &mut SwankyRng,
    circuit: &C,
) {
    swanky_channel::local::local_channel_pair(
        |c| {
            let mut gb = Garbler::new(circuit, c, rng_gb)?;
            let mut inputs = gb.encode_many(inputs_gb, &vec![2; inputs_gb.len()], c)?;
            let theirs = gb.receive_many(&vec![2; inputs_ev.len()], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<_>>>::map(circuit, inputs),
                c,
            )?;
            gb.outputs(&outputs.flatten(), c)
        },
        |c| {
            let mut ev = Evaluator::new(circuit, c, rng_ev)?;
            let mut inputs = ev.receive_many(&vec![2; inputs_gb.len()], c)?;
            let mine = ev.encode_many(inputs_ev, &vec![2; inputs_ev.len()], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator>>::map(circuit, inputs),
                c,
            )?;
            ev.outputs(&outputs.flatten(), c)
        },
    )
    .unwrap();
}
