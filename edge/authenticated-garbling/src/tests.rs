#![cfg(test)]

use crate::evaluator::Evaluator;
use crate::garbler::Garbler;

use fancy_garbling::{Fancy, circuit::circuits};
use swanky_field_binary::F2;
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
    let circuit = circuits::TestBinaryAddition(input_size);
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
    let input_size = 400;
    let circuit = circuits::TestBinaryAddition(input_size);

    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(rng, c).unwrap();
            gb.preprocess_circuit(&circuit, c).unwrap();
            gb.encode_many(&vec![0; input_size], &vec![2; input_size], c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng).unwrap();
            ev.preprocess_circuit(&circuit, c).unwrap();
            ev.set_values(vec![F2::from(0); input_size]);
            ev.receive_many(&vec![2; input_size], c)
        },
    )
    .unwrap();
}
