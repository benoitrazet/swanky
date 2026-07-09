use fancy_analyzer::CircuitAnalyzer;
use fancy_plaintext::Dummy;
use fancy_traits::{CircuitInputMapper, FancyEncode, FancyOutput};
use swanky_authenticated_garbling::{
    EvaluatorOffline, EvaluatorOnline, GarblerOffline, GarblerValidator, PartyEvaluator,
    PartyGarbler, WirePreProcessor,
};
use swanky_rng::SwankyRng;

/// Circuit Runner
pub fn test_circuit<
    C: CircuitInputMapper<CircuitAnalyzer>
        + CircuitInputMapper<WirePreProcessor<PartyGarbler>>
        + CircuitInputMapper<WirePreProcessor<PartyEvaluator>>
        + CircuitInputMapper<GarblerOffline>
        + CircuitInputMapper<EvaluatorOnline>
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
            let gb = GarblerOffline::initialize(circuit, c, rng_gb)?;

            let (outputs, gb) = gb.execute(circuit)?;
            let mut gb = gb.finalize(c)?;

            let mut inputs = gb.encode_many(inputs_gb, &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let validator = gb.finalize(c)?;
            let mut validator = validator.validate(circuit, inputs, c)?;
            validator.outputs(&outputs, c)
        },
        |c| {
            let ev = EvaluatorOffline::initialize(circuit, c, rng_ev)?;
            let mut ev = ev.finalize(c)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(inputs_ev, &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let (outputs, ev) = ev.execute(circuit, inputs)?;
            let ev = ev.finalize(c)?;
            let mut ev = ev.validate(c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
}
