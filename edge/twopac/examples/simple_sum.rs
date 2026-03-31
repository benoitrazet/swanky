//! An example that adds two secret numbers in a binary garbled circuit
//! using fancy-garbling.
use fancy_garbling::{
    AllWire, BinaryBundle, BinaryGadgets, Fancy, FancyArithmetic, FancyBinary, FancyInput,
    FancyReveal, util,
};
use swanky_twopac::semihonest::{Evaluator, Garbler};

use swanky_channel::Channel;
use swanky_ot_alsz_kos::alsz::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;

/// A structure that contains both the garbler and the evaluators
/// wires. This structure simplifies the API of the garbled circuit.
struct SUMInputs<F> {
    pub garbler_wires: BinaryBundle<F>,
    pub evaluator_wires: BinaryBundle<F>,
}

/// The garbler's main method:
/// (1) The garbler is first created using the passed rng and value.
/// (2) The garbler then exchanges their wires obliviously with the evaluator.
/// (3) The garbler and the evaluator then run the garbled circuit.
/// (4) The garbler and the evaluator open the result of the computation.
fn gb_sum(rng: &mut SwankyRng, channel: &mut Channel, input: u128) {
    // (1)
    let mut gb = Garbler::<SwankyRng, OtSender, AllWire>::new(channel, rng.clone()).unwrap();
    // (2)
    let circuit_wires = gb_set_fancy_inputs(&mut gb, input, channel);
    // (3)
    let sum = fancy_sum::<Garbler<SwankyRng, OtSender, AllWire>>(&mut gb, circuit_wires, channel)
        .unwrap();
    // (4)
    gb.outputs(sum.wires(), channel).unwrap();
}

/// The garbler's wire exchange method
fn gb_set_fancy_inputs<F>(gb: &mut F, input: u128, channel: &mut Channel) -> SUMInputs<F::Item>
where
    F: FancyInput<Item = AllWire>,
{
    // The number of bits needed to represent a single input, in this case a u128
    let nbits = 128;
    // The garbler encodes their input into binary wires
    let garbler_wires: BinaryBundle<F::Item> = gb.bin_encode(input, nbits, channel).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT)
    let evaluator_wires: BinaryBundle<F::Item> = gb.bin_receive(nbits, channel).unwrap();

    SUMInputs {
        garbler_wires,
        evaluator_wires,
    }
}

/// The evaluator's main method:
/// (1) The evaluator is first created using the passed rng and value.
/// (2) The evaluator then exchanges their wires obliviously with the garbler.
/// (3) The evaluator and the garbler then run the garbled circuit.
/// (4) The evaluator and the garbler open the result of the computation.
/// (5) The evaluator translates the binary output of the circuit into its decimal
///     representation.
fn ev_sum(rng: &mut SwankyRng, channel: &mut Channel, input: u128) -> u128 {
    // (1)
    let mut ev = Evaluator::<SwankyRng, OtReceiver, AllWire>::new(channel, rng.clone()).unwrap();
    // (2)
    let circuit_wires = ev_set_fancy_inputs(&mut ev, input, channel);
    // (3)
    let sum =
        fancy_sum::<Evaluator<SwankyRng, OtReceiver, AllWire>>(&mut ev, circuit_wires, channel)
            .unwrap();

    // (4)
    let sum_binary = ev
        .outputs(sum.wires(), channel)
        .unwrap()
        .expect("evaluator should produce outputs");
    // (5)
    util::u128_from_bits(&sum_binary)
}

/// The evaluator's wire exchange method
fn ev_set_fancy_inputs<F>(ev: &mut F, input: u128, channel: &mut Channel) -> SUMInputs<F::Item>
where
    F: FancyInput<Item = AllWire>,
{
    // The number of bits needed to represent a single input, in this case a u128
    let nbits = 128;
    // The evaluator receives the garblers input labels.
    let garbler_wires: BinaryBundle<F::Item> = ev.bin_receive(nbits, channel).unwrap();
    // The evaluator receives their input labels using Oblivious Transfer (OT).
    let evaluator_wires: BinaryBundle<F::Item> = ev.bin_encode(input, nbits, channel).unwrap();

    SUMInputs {
        garbler_wires,
        evaluator_wires,
    }
}

/// The main fancy function which describes the garbled circuit for summation.
fn fancy_sum<F>(
    f: &mut F,
    wire_inputs: SUMInputs<F::Item>,
    channel: &mut Channel,
) -> swanky_error::Result<BinaryBundle<F::Item>>
where
    F: FancyReveal + Fancy + BinaryGadgets + FancyBinary + FancyArithmetic,
{
    // The garbler and the evaluator's values are added together.
    // For simplicity we assume that the addition will not result
    // in a carry.
    let sum = f.bin_addition_no_carry(
        &wire_inputs.garbler_wires,
        &wire_inputs.evaluator_wires,
        channel,
    )?;

    Ok(sum)
}

fn sum_in_clear(gb_value: u128, ev_value: u128) -> u128 {
    gb_value + ev_value
}

use clap::Parser;
#[derive(Parser)]
/// Example usage:
///
/// cargo run --example simple_sum 2 3
///
/// Computes the SUM(2,3)
/// Where 2 is the garbler's value and 3 the evaluator's
struct Cli {
    /// The first integer the garbler's value
    gb_value: u128,
    /// The second integer the evaluator's value
    ev_value: u128,
}

fn main() {
    let cli = Cli::parse();
    let gb_value: u128 = cli.gb_value;
    let ev_value: u128 = cli.ev_value;

    let (_, result) = swanky_channel::local::local_channel_pair(
        |channel| {
            let rng_gb = SwankyRng::new();
            gb_sum(&mut rng_gb.clone(), channel, gb_value);
            Ok(())
        },
        |channel| {
            let rng_ev = SwankyRng::new();
            let result = ev_sum(&mut rng_ev.clone(), channel, ev_value);
            Ok(result)
        },
    )
    .unwrap();

    let sum = sum_in_clear(gb_value, ev_value);

    println!("Garbled Circuit result is : SUM({gb_value}, {ev_value}) = {result}");
    assert!(
        result == sum,
        "The garbled circuit result is incorrect and sould be {sum}"
    );
}
