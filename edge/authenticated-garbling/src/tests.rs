#![cfg(test)]

use crate::evaluator::Evaluator;
use crate::garbler::Garbler;

use fancy_garbling::{Fancy, circuit::circuits};
use swanky_rng::SwankyRng;

#[test]
fn test_party_construction_passes() {
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            Garbler::new(rng, c)
        },
        |c| {
            let rng = SwankyRng::new();
            Evaluator::new(c, rng)
        },
    )
    .unwrap();
}
#[test]
fn test_party_preprocessing_passes() {
    let input_size = 400;
    let circuit = circuits::TestAndGateFanN(input_size);
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(rng, c).unwrap();
            gb.preprocess_circuit(&circuit, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng).unwrap();
            ev.preprocess_circuit(&circuit, c)
        },
    )
    .unwrap();
}
#[test]
fn test_party_encoding_receiving_passes() {
    let input_size_gb = 400;
    let input_size_ev = 400;
    let circuit = circuits::TestAndGateFanN(input_size_gb + input_size_ev);

    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(rng, c)?;
            gb.preprocess_circuit(&circuit, c)?;
            gb.encode_many(&vec![0; input_size_gb], &vec![2; input_size_gb], c)?;
            gb.receive_many(&vec![2; input_size_ev], c)?;
            Ok(())
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng)?;
            ev.preprocess_circuit(&circuit, c)?;
            ev.receive_many(&vec![2; input_size_gb], c)?;
            ev.encode_many(&vec![0; input_size_ev], &vec![2; input_size_ev], c)?;
            Ok(())
        },
    )
    .unwrap();
}
