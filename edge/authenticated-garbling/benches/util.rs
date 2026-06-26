use fancy_garbling::{
    CircuitInputMapper, FancyEncode, Flatten, circuit_analyzer::CircuitAnalyzer, dummy::Dummy,
};
use swanky_authenticated_garbling::{
    Evaluator, GarblerOffline, GarblerValidator, WirePreProcessor,
    ps::{PartyEvaluator, PartyGarbler},
};
use swanky_rng::SwankyRng;

/// Circuit Runner
pub fn test_circuit<
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<GarblerOffline>
        + CircuitInputMapper<Evaluator>
        + CircuitInputMapper<Dummy>
        + CircuitInputMapper<GarblerValidator>
        + Sync,
>(
    inputs_gb: &[u16],
    inputs_ev: &[u16],
    rng_gb: &mut SwankyRng,
    rng_ev: &mut SwankyRng,
    circuit: &C,
) {
    let ninputs_gb = inputs_gb.len();
    let ninputs_ev = inputs_ev.len();
    swanky_channel::local::local_channel_pair(
        |c| {
            let gb = GarblerOffline::new(circuit, c, rng_gb)?;

            let (mut gb, outputs) = gb.execute(circuit)?;

            let mut inputs = gb.encode_many(inputs_gb, &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            gb.finalize(circuit, inputs, &outputs.flatten(), c)
        },
        |c| {
            let mut ev = Evaluator::new(circuit, c, rng_ev)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(inputs_ev, &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(
                &mut ev,
                <C as CircuitInputMapper<Evaluator>>::map(circuit, inputs),
                c,
            )?;
            ev.finalize(&outputs.flatten(), c)
        },
    )
    .unwrap();
}
