#![cfg(test)]

use crate::evaluator::Evaluator;
use crate::garbler::Garbler;

use fancy_garbling::{BinaryBundle, BinaryGadgets, Fancy, FancyBinary};
use swanky_channel::Channel;
use swanky_field_binary::F2;
use swanky_rng::SwankyRng;

fn fancy_sum<F>(
    f: &mut F,
    garbler_wires: BinaryBundle<F::Item>,
    evaluator_wires: BinaryBundle<F::Item>,
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>>
where
    F: Fancy + BinaryGadgets + FancyBinary,
{
    f.bin_addition_no_carry(&garbler_wires, &evaluator_wires, channel)
}
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
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(rng, c).unwrap();
            gb.preprocess_circuit(&fancy_sum, input_size, c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng).unwrap();
            ev.preprocess_circuit(&fancy_sum, input_size, c)
        },
    )
    .unwrap();
}
#[test]
fn test_party_encoding_receiving_passes() {
    let gb_input_size = 400;
    let ev_input_size = 500;

    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(rng, c).unwrap();
            gb.preprocess_circuit(&fancy_sum, gb_input_size, c).unwrap();
            gb.encode_many(&vec![0; gb_input_size], &vec![2; gb_input_size], c)
        },
        |c| {
            let rng = SwankyRng::new();
            let mut ev = Evaluator::new(c, rng).unwrap();
            ev.preprocess_circuit(&fancy_sum, ev_input_size, c).unwrap();
            ev.set_values(vec![F2::from(0); ev_input_size]);
            ev.receive_many(&vec![2; ev_input_size], c)
        },
    )
    .unwrap();
}
