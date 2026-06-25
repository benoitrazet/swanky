use fancy_garbling::{
    CircuitInputMapper, FancyEncode, FancyOutput, Flatten, circuit_analyzer::CircuitAnalyzer,
    dummy::Dummy,
};
use swanky_authenticated_garbling::{
    Evaluator, Garbler, GarblerValidator, WirePreProcessor,
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
        + for<'c> CircuitInputMapper<GarblerValidator<'c, SwankyRng>>
        + Sync,
>(
    inputs_gb: &[u16],
    inputs_ev: &[u16],
    rng_gb: SwankyRng,
    rng_ev: &mut SwankyRng,
    circuit: &C,
) {
    let ninputs_gb = inputs_gb.len();
    let ninputs_ev = inputs_ev.len();
    swanky_channel::local::local_channel_pair(
        |c| {
            let mut gb = Garbler::new(circuit, c, rng_gb)?;
            let offline_wires = gb.offline_wires();
            let outputs = circuit.execute(
                &mut gb,
                <C as CircuitInputMapper<Garbler<_>>>::map(circuit, offline_wires),
                c,
            )?;
            let mut inputs = gb.encode_many(inputs_gb, &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_gb], c)?;
            inputs.extend(theirs);
            gb.validate(circuit, inputs, c).unwrap();
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
