use fancy_garbling::{
    Fancy, circuit::CircuitExecutor, circuit_analyzer::CircuitAnalyzer, dummy::Dummy,
};
use swanky_authenticated_garbling::{
    Evaluator, Garbler, WirePreProcessor,
    ps::{PartyEvaluator, PartyGarbler},
};
use swanky_rng::SwankyRng;

/// Circuit Runner
pub fn test_circuit<
    C: CircuitExecutor<CircuitAnalyzer>
        + CircuitExecutor<WirePreProcessor<PartyGarbler>>
        + CircuitExecutor<WirePreProcessor<PartyEvaluator>>
        + CircuitExecutor<Garbler<SwankyRng>>
        + CircuitExecutor<Evaluator>
        + CircuitExecutor<Dummy>
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
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let mut ev = Evaluator::new(circuit, c, rng_ev)?;
            let mut inputs = ev.receive_many(&vec![2; inputs_gb.len()], c)?;
            let mine = ev.encode_many(inputs_ev, &vec![2; inputs_ev.len()], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
}
